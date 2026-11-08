package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
)

func main() {
	_ = flag.String("target", "", "ignored compatibility flag")
	displayName := flag.String("display-name", "", "trusted test mode")
	_ = flag.Bool("sandboxed", false, "ignored compatibility flag")
	_ = flag.Bool("resource-limited", false, "ignored compatibility flag")
	audit := flag.String("omarchy-audit", "", "optional evidence path")
	_ = flag.String("omarchy-audit-format", "", "ignored pinned format")
	flag.Parse()
	if *displayName == "timeout" {
		time.Sleep(10 * time.Second)
		return
	}
	if *displayName == "output" {
		_, _ = os.Stdout.Write(make([]byte, 17<<20))
		return
	}
	if *displayName == "diagnostic-output" {
		_, _ = os.Stderr.Write(make([]byte, 65<<10))
		time.Sleep(10 * time.Second)
		return
	}
	result := map[string]bool{
		"readHostEtc":         canRead("/etc/passwd"),
		"readHostHome":        canRead("/home"),
		"readTarget":          canRead("/target/manifest.json"),
		"writeTarget":         canWrite("/target/probe-write"),
		"writeTmp":            canWrite("/tmp/probe-write"),
		"network":             canConnect(),
		"seeHostProc":         canRead("/proc/1/status"),
		"seeSessionSocket":    canRead(fmt.Sprintf("/run/user/%d/bus", os.Getuid())) || canRead("/tmp/.X11-unix"),
		"nestedUserNamespace": canCreateUserNamespace(),
		"environmentMinimal":  minimalEnvironment(),
		"readAudit":           *audit != "" && canRead(*audit),
		"writeAudit":          *audit != "" && canWrite(*audit),
		"readAuditSibling":    canRead("/audit/sibling"),
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}

func canCreateUserNamespace() bool {
	_, _, errno := syscall.RawSyscall(syscall.SYS_UNSHARE, uintptr(syscall.CLONE_NEWUSER), 0, 0)
	return errno == 0
}

func canRead(name string) bool {
	_, err := os.ReadFile(name)
	return err == nil
}

func canWrite(name string) bool {
	err := os.WriteFile(name, []byte("probe"), 0o600)
	if err == nil {
		_ = os.Remove(name)
	}
	return err == nil
}

func canConnect() bool {
	connection, err := net.DialTimeout("tcp", "1.1.1.1:53", 100*time.Millisecond)
	if err == nil {
		_ = connection.Close()
		return true
	}
	return false
}

func minimalEnvironment() bool {
	allowed := map[string]bool{"HOME": true, "PATH": true, "PWD": true, "TMPDIR": true}
	for _, entry := range os.Environ() {
		for index := 0; index < len(entry); index++ {
			if entry[index] == '=' {
				if !allowed[entry[:index]] {
					return false
				}
				break
			}
		}
	}
	return os.Getenv("HOME") == "/nonexistent" && os.Getenv("PATH") == "/app" && os.Getenv("PWD") == "/target"
}
