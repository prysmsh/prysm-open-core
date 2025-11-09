package daemon

import (
	_ "embed"
	"runtime"
)

//go:generate go run build_assets.go
var (
	//go:embed assets/linux-amd64/prysm-meshd
	meshdLinuxAMD64 []byte
	//go:embed assets/linux-arm64/prysm-meshd
	meshdLinuxARM64 []byte
)

func embeddedBinary() ([]byte, string, bool) {
	switch runtime.GOOS {
	case "linux":
		switch runtime.GOARCH {
		case "amd64":
			if len(meshdLinuxAMD64) == 0 {
				return nil, "", false
			}
			return meshdLinuxAMD64, "prysm-meshd", true
		case "arm64":
			if len(meshdLinuxARM64) == 0 {
				return nil, "", false
			}
			return meshdLinuxARM64, "prysm-meshd", true
		}
	}
	return nil, "", false
}
