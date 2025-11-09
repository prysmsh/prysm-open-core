//go:build ignore

package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

var targets = []struct {
	goos   string
	goarch string
}{
	{"linux", "amd64"},
	{"linux", "arm64"},
}

func main() {
	wd, err := os.Getwd()
	if err != nil {
		log.Fatalf("determine working directory: %v", err)
	}

	// repo root: ../../.. from prysm-cli/internal/daemon
	repoRoot := filepath.Clean(filepath.Join(wd, "..", "..", ".."))
	meshDir := filepath.Join(repoRoot, "prysm-meshd")
	if _, err := os.Stat(meshDir); err != nil {
		log.Fatalf("prysm-meshd source not found at %s: %v", meshDir, err)
	}

	for _, target := range targets {
		outDir := filepath.Join(wd, "assets", fmt.Sprintf("%s-%s", target.goos, target.goarch))
		if err := os.MkdirAll(outDir, 0o755); err != nil {
			log.Fatalf("create asset directory: %v", err)
		}

		outName := "prysm-meshd"
		if target.goos == "windows" {
			outName += ".exe"
		}
		outPath := filepath.Join(outDir, outName)

		cmd := exec.Command("go", "build", "-trimpath", "-ldflags", "-s -w", "-o", outPath, "./cmd/prysm-meshd")
		cmd.Dir = meshDir
		cmd.Env = append(os.Environ(),
			"CGO_ENABLED=0",
			"GOOS="+target.goos,
			"GOARCH="+target.goarch,
		)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		log.Printf("building prysm-meshd for %s/%s", target.goos, target.goarch)
		if err := cmd.Run(); err != nil {
			log.Fatalf("build failed for %s/%s: %v", target.goos, target.goarch, err)
		}
	}
}
