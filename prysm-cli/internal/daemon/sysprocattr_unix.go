//go:build !windows

package daemon

import "syscall"

func buildSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
