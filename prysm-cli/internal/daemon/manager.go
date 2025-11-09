package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	envMeshdPath          = "PRYSM_MESHD_PATH"
	defaultStartupTimeout = 10 * time.Second
	pidFileName           = "meshd.pid"
	logFileName           = "meshd.log"
)

// Manager supervises the lifecycle of prysm-meshd on the local machine.
type Manager struct {
	socketPath string
	stateDir   string
	pidFile    string
	logFile    string
	binaryPath string
}

// NewManager constructs a lifecycle manager bound to the provided CLI home directory.
func NewManager(homeDir, socketPath string) (*Manager, error) {
	homeDir = strings.TrimSpace(homeDir)
	if homeDir == "" {
		return nil, fmt.Errorf("home directory is required")
	}

	stateDir := filepath.Join(homeDir, "meshd")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, fmt.Errorf("create meshd state dir: %w", err)
	}

	if socketPath = strings.TrimSpace(socketPath); socketPath == "" {
		if env := strings.TrimSpace(os.Getenv("PRYSM_MESHD_SOCKET")); env != "" {
			socketPath = env
		} else {
			socketPath = filepath.Join(stateDir, "meshd.sock")
		}
	}

	if err := os.MkdirAll(filepath.Dir(socketPath), 0o755); err != nil {
		return nil, fmt.Errorf("prepare socket directory: %w", err)
	}

	return &Manager{
		socketPath: socketPath,
		stateDir:   stateDir,
		pidFile:    filepath.Join(stateDir, pidFileName),
		logFile:    filepath.Join(stateDir, logFileName),
	}, nil
}

// Socket returns the configured Unix domain socket path.
func (m *Manager) Socket() string {
	return m.socketPath
}

// StateDir returns the directory used for daemon state/logs.
func (m *Manager) StateDir() string {
	return m.stateDir
}

// LogFile returns the path used for daemon logs.
func (m *Manager) LogFile() string {
	return m.logFile
}

// Status describes the current health of the managed daemon.
type Status struct {
	State     string    `json:"state"`
	PID       int       `json:"pid"`
	Socket    string    `json:"socket"`
	LogFile   string    `json:"log_file"`
	CheckedAt time.Time `json:"checked_at"`
}

// Status returns a lightweight snapshot describing the daemon state.
func (m *Manager) Status(ctx context.Context) (*Status, error) {
	running, pid, err := m.IsRunning(ctx)
	if err != nil {
		return nil, err
	}

	state := "down"
	if running {
		state = "up"
	}

	return &Status{
		State:     state,
		PID:       pid,
		Socket:    m.socketPath,
		LogFile:   m.logFile,
		CheckedAt: time.Now().UTC(),
	}, nil
}

// Start ensures the daemon is running, launching it if necessary.
func (m *Manager) Start(ctx context.Context) error {
	if running, _, err := m.IsRunning(ctx); err != nil {
		return err
	} else if running {
		return nil
	}

	bin, err := m.resolveBinary()
	if err != nil {
		return err
	}

	if err := os.Remove(m.socketPath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove stale socket: %w", err)
	}

	logFile, err := os.OpenFile(m.logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	defer logFile.Close()

	args := []string{"--socket", m.socketPath}
	if m.stateDir != "" {
		args = append(args, "--state-dir", m.stateDir)
	}

	cmd := exec.Command(bin, args...)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.Env = os.Environ()

	cmd.SysProcAttr = buildSysProcAttr()

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("launch prysm-meshd: %w", err)
	}

	pid := cmd.Process.Pid
	if err := os.WriteFile(m.pidFile, []byte(strconv.Itoa(pid)), 0o600); err != nil {
		return fmt.Errorf("record meshd pid: %w", err)
	}

	if err := cmd.Process.Release(); err != nil && !errors.Is(err, syscall.EINVAL) {
		return fmt.Errorf("release meshd handle: %w", err)
	}

	startCtx, cancel := context.WithTimeout(ctx, defaultStartupTimeout)
	defer cancel()
	if err := m.waitForReady(startCtx); err != nil {
		return fmt.Errorf("wait meshd ready: %w", err)
	}

	return nil
}

// Stop terminates the daemon process if it is running.
func (m *Manager) Stop(ctx context.Context) error {
	running, pid, err := m.IsRunning(ctx)
	if err != nil {
		return err
	}
	if !running || pid == 0 {
		_ = os.Remove(m.pidFile)
		return nil
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		_ = os.Remove(m.pidFile)
		return nil
	}

	if runtime.GOOS == "windows" {
		if err := proc.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("terminate meshd: %w", err)
		}
	} else {
		if err := proc.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("signal meshd: %w", err)
		}
	}

	waitCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("meshd did not exit in time: %w", waitCtx.Err())
		case <-ticker.C:
			alive, _ := processAlive(pid)
			if !alive {
				_ = os.Remove(m.pidFile)
				_ = os.Remove(m.socketPath)
				return nil
			}
		}
	}
}

// Restart forces the daemon to restart.
func (m *Manager) Restart(ctx context.Context) error {
	if err := m.Stop(ctx); err != nil {
		return err
	}
	return m.Start(ctx)
}

// IsRunning checks whether prysm-meshd is responsive.
func (m *Manager) IsRunning(ctx context.Context) (bool, int, error) {
	pid, err := m.readPID()
	if err != nil {
		return false, 0, err
	}
	if pid == 0 {
		return false, 0, nil
	}

	statusCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	client := NewClient(m.socketPath)
	if _, err := client.Status(statusCtx); err == nil {
		return true, pid, nil
	}

	alive, err := processAlive(pid)
	if err != nil {
		return false, 0, err
	}
	if !alive {
		_ = os.Remove(m.pidFile)
		_ = os.Remove(m.socketPath)
		return false, 0, nil
	}

	return false, pid, nil
}

func (m *Manager) waitForReady(ctx context.Context) error {
	client := NewClient(m.socketPath)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			checkCtx, cancel := context.WithTimeout(ctx, 1*time.Second)
			_, err := client.Status(checkCtx)
			cancel()
			if err == nil {
				return nil
			}
		}
	}
}

func (m *Manager) readPID() (int, error) {
	data, err := os.ReadFile(m.pidFile)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read meshd pid file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parse meshd pid: %w", err)
	}
	return pid, nil
}

func (m *Manager) resolveBinary() (string, error) {
	if m.binaryPath != "" {
		return m.binaryPath, nil
	}

	if env := strings.TrimSpace(os.Getenv(envMeshdPath)); env != "" {
		if _, err := os.Stat(env); err == nil {
			m.binaryPath = env
			return env, nil
		}
	}

	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		name := "prysm-meshd"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		candidate := filepath.Join(dir, name)
		if _, err := os.Stat(candidate); err == nil {
			m.binaryPath = candidate
			return candidate, nil
		}
	}

	if path, err := exec.LookPath("prysm-meshd"); err == nil {
		m.binaryPath = path
		return path, nil
	}

	return "", fmt.Errorf("prysm-meshd binary not found (set %s or add to PATH)", envMeshdPath)
}
