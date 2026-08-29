package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	_ = flag.String("target", "", "ignored compatibility flag")
	displayName := flag.String("display-name", "", "trusted test mode")
	_ = flag.Bool("sandboxed", false, "ignored compatibility flag")
	_ = flag.Bool("resource-limited", false, "ignored compatibility flag")
	flag.Parse()
	if *displayName == "timeout" {
		time.Sleep(10 * time.Second)
		return
	}
	if *displayName == "output" {
		_, _ = os.Stdout.Write(make([]byte, 17<<20))
		return
	}
	if *displayName == "both-output" {
		done := make(chan struct{}, 2)
		go func() { _, _ = os.Stdout.Write(make([]byte, 17<<20)); done <- struct{}{} }()
		go func() { _, _ = os.Stderr.Write(make([]byte, 1<<20)); done <- struct{}{} }()
		<-done
		<-done
		return
	}
	if *displayName == "hold-stdout" || *displayName == "hold-stderr" {
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		for {
			time.Sleep(time.Second)
		}
	}
	if *displayName == "stdout-overflow-stderr-held" || *displayName == "stderr-overflow-stdout-held" {
		heldMode := "hold-stderr"
		if *displayName == "stderr-overflow-stdout-held" {
			heldMode = "hold-stdout"
		}
		child := exec.Command("/app/plug-prejudice", "--target", "/target", "--display-name", heldMode, "--sandboxed", "--resource-limited")
		child.Stdin = os.Stdin
		if heldMode == "hold-stderr" {
			child.Stderr = os.Stderr
			child.Stdout = io.Discard
		} else {
			child.Stdout = os.Stdout
			child.Stderr = io.Discard
		}
		if err := child.Start(); err != nil {
			panic(err)
		}
		if *displayName == "stdout-overflow-stderr-held" {
			_, _ = os.Stdout.Write(make([]byte, 17<<20))
		} else {
			_, _ = os.Stderr.Write(make([]byte, 1<<20))
		}
		return
	}
	if *displayName == "descendant-child" {
		signal.Ignore(syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
		ready := os.NewFile(3, "readiness")
		if ready == nil {
			panic("readiness descriptor unavailable")
		}
		_, _ = ready.Write([]byte{1})
		_ = ready.Close()
		for {
			time.Sleep(time.Second)
		}
	}
	if *displayName == "descendant" {
		readinessReader, readinessWriter, err := os.Pipe()
		if err != nil {
			panic(err)
		}
		child := exec.Command("/app/plug-prejudice", "--target", "/target", "--display-name", "descendant-child", "--sandboxed", "--resource-limited")
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		child.ExtraFiles = []*os.File{readinessWriter}
		if err := child.Start(); err != nil {
			panic(err)
		}
		_ = readinessWriter.Close()
		var ready [1]byte
		if _, err := readinessReader.Read(ready[:]); err != nil {
			panic(err)
		}
		_ = readinessReader.Close()
		_, _ = fmt.Fprintf(os.Stderr, "descendant=%d\n", child.Process.Pid)
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
		"cgroupMigration":     canMigrateCgroup(),
		"environmentMinimal":  minimalEnvironment(),
	}
	_ = json.NewEncoder(os.Stdout).Encode(result)
}

func canMigrateCgroup() bool {
	return os.WriteFile("/sys/fs/cgroup/cgroup.procs", []byte(strconv.Itoa(os.Getpid())), 0o600) == nil
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
