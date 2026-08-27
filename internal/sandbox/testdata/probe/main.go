package main

import (
	"encoding/json"
	"flag"
	"net"
	"os"
	"time"
)

func main() {
	_ = flag.String("target", "", "ignored compatibility flag")
	_ = flag.String("display-name", "", "ignored compatibility flag")
	_ = flag.Bool("sandboxed", false, "ignored compatibility flag")
	flag.Parse()
	result := map[string]bool{
		"readHostEtc":        canRead("/etc/passwd"),
		"readHostHome":       canRead("/home"),
		"readTarget":         canRead("/target/manifest.json"),
		"writeTarget":        canWrite("/target/probe-write"),
		"writeTmp":           canWrite("/tmp/probe-write"),
		"network":            canConnect(),
		"seeHostProc":        canRead("/proc/1/status"),
		"environmentMinimal": minimalEnvironment(),
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
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
