// This file contains the e2e tests for the netstat package.
// In perticular, it tests the following:
// * The Netstat() function returns the correct number of sockets
// * The Netstat() function returns the correct number of sockets for a given namespace
// * The Netstat() function returns the correct number of sockets for a given namespace and protocol
// * Intermediary functions like procFiles() and openFileStream()

package netstat_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"strconv"
	"syscall"
	"testing"

	"github.com/nberlee/go-netstat/common"
	"github.com/nberlee/go-netstat/netns"
	"github.com/nberlee/go-netstat/netstat"
)

type testResultCount int

const (
	tcp testResultCount = iota + 1
	tcp6
	udp
	udp6
	udplite
	udplite6
	raw
	raw6
	containerPid1000tcp
	containerPid1000tcp6
	containerPid1000udp
	containerPid1000udp6
	containerPid1000udplite
	containerPid1000udplite6
	containerPid1000raw
	containerPid1000raw6
	containerNetNS1tcp
	containerNetNS1tcp6
	containerNetNS1udp
	containerNetNS1udp6
	containerNetNS1udplite
	containerNetNS1udplite6
	containerNetNS1raw
	containerNetNS1raw6
	containerNetNS2tcp
	containerNetNS2tcp6
	containerNetNS2udp
	containerNetNS2udp6
	containerNetNS2udplite
	containerNetNS2udplite6
	containerNetNS2raw
	containerNetNS2raw6
)

type commontests struct {
	procTmpDir      string
	netNsPathTmpDir string
	testLine        string
}

func (ct *commontests) writeProcNetSocktab(protocol string, lines int) {
	file, err := os.Create(path.Join(ct.procTmpDir, "net", protocol))
	if err != nil {
		panic(err)
	}
	file.WriteString("sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")

	defer file.Close()
	for i := 0; i < lines; i++ {
		file.WriteString(strconv.Itoa(i) + ": " + ct.testLine)
	}
}

func (ct *commontests) writeProcNetSocktabWithPid(protocol string, pid int, lines int) {
	pidPath := path.Join(ct.procTmpDir, strconv.FormatUint(uint64(pid), 10))
	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		err := os.Mkdir(pidPath, 0755)
		if err != nil {
			panic(err)
		}
	}
	if _, err := os.Stat(path.Join(pidPath, "net")); os.IsNotExist(err) {
		err = os.Mkdir(path.Join(pidPath, "net"), 0755)
		if err != nil {
			panic(err)
		}
	}

	if _, err := os.Stat(path.Join(pidPath, "fd")); os.IsNotExist(err) {
		fdPath := path.Join(pidPath, "fd")
		err := os.Mkdir(fdPath, 0755)
		if err != nil {
			panic(err)
		}
	}

	file, err := os.Create(path.Join(pidPath, "net", protocol))
	if err != nil {
		panic(err)
	}
	defer file.Close()
	file.WriteString("sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	for i := 0; i < lines; i++ {
		file.WriteString(strconv.Itoa(i) + ": " + ct.testLine)
	}
}

func (ct *commontests) createNetNsContainer(netNsName string, pid int, fd int) {
	pidPath := path.Join(ct.procTmpDir, strconv.FormatUint(uint64(pid), 10))
	if _, err := os.Stat(pidPath); os.IsNotExist(err) {
		err := os.Mkdir(pidPath, 0755)
		if err != nil {
			panic(err)
		}
	}
	nsPath := path.Join(pidPath, "ns")
	err := os.Mkdir(nsPath, 0755)
	if err != nil {
		panic(err)
	}

	netNsPath := path.Join(nsPath, "net")
	err = os.Symlink(fmt.Sprintf("net:[%d]", fd), netNsPath)
	if err != nil {
		panic(err)
	}

	symlinkPath := path.Join(ct.netNsPathTmpDir, netNsName)
	err = os.Symlink("/proc/self/ns/net", symlinkPath)
	if err != nil {
		panic(err)
	}

	// Create the fd directory
	fdPath := path.Join(pidPath, "fd")
	err = os.Mkdir(fdPath, 0755)
	if err != nil {
		panic(err)
	}

	// Create the symlink
	err = os.Symlink(fmt.Sprintf("net:[%d]", fd), path.Join(fdPath, strconv.Itoa(1)))
	if err != nil {
		panic(err)
	}
}

func (ct *commontests) createProcess(fileDescriptor int, pid int, processName string) {
	// Create the process directory
	processPath := path.Join(ct.procTmpDir, strconv.FormatUint(uint64(pid), 10))
	err := os.Mkdir(processPath, 0755)
	if err != nil {
		panic(err)
	}

	// Create the fd directory
	fdPath := path.Join(processPath, "fd")
	err = os.Mkdir(fdPath, 0755)
	if err != nil {
		panic(err)
	}

	// Create the symlink
	err = os.Symlink(fmt.Sprintf("socket:[%d]", fileDescriptor), path.Join(fdPath, strconv.Itoa(fileDescriptor)))
	if err != nil {
		panic(err)
	}

	statContent := []byte(fmt.Sprintf("%d (%s) S 0 0 0 0 -1 4194560 0", pid, processName))
	err = os.WriteFile(path.Join(ct.procTmpDir, strconv.FormatUint(uint64(pid), 10), "stat"), statContent, 0644)
	if err != nil {
		panic(err)
	}
}

func (ct *commontests) setupMock() {
	var err error
	ct.procTmpDir, err = os.MkdirTemp("", "proc")
	if err != nil {
		panic(err)
	}
	common.ProcPath = ct.procTmpDir
	os.Mkdir(path.Join(ct.procTmpDir, "net"), 0755)

	ct.netNsPathTmpDir, err = os.MkdirTemp("", "netns")
	if err != nil {
		panic(err)
	}
	netns.NetNSPath = ct.netNsPathTmpDir

	ct.testLine = "11111111:2222 33333333:4444 01 00000001:00000001 01:00000001 00000001  1000        1 784045 1 0000000000000001 1 1 1 1 1\n"
	ct.writeProcNetSocktab("tcp", int(tcp))
	ct.writeProcNetSocktab("tcp6", int(tcp6))
	ct.writeProcNetSocktab("udp", int(udp))
	ct.writeProcNetSocktab("udp6", int(udp6))
	ct.writeProcNetSocktab("udplite", int(udplite))
	ct.writeProcNetSocktab("udplite6", int(udplite6))
	ct.writeProcNetSocktab("raw", int(raw))
	ct.writeProcNetSocktab("raw6", int(raw6))
	ct.writeProcNetSocktabWithPid("tcp", 1000, int(containerPid1000tcp))
	ct.writeProcNetSocktabWithPid("tcp6", 1000, int(containerPid1000tcp6))
	ct.writeProcNetSocktabWithPid("udp", 1000, int(containerPid1000udp))
	ct.writeProcNetSocktabWithPid("udp6", 1000, int(containerPid1000udp6))
	ct.writeProcNetSocktabWithPid("udplite", 1000, int(containerPid1000udplite))
	ct.writeProcNetSocktabWithPid("udplite6", 1000, int(containerPid1000udplite6))
	ct.writeProcNetSocktabWithPid("raw", 1000, int(containerPid1000raw))
	ct.writeProcNetSocktabWithPid("raw6", 1000, int(containerPid1000raw6))
	fileInfo, err := os.Stat("/proc/self/ns/net")
	if err != nil {
		panic(err)
	}

	stat, ok := fileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		panic("failed to get inode")
	}
	ct.createNetNsContainer("testnsnet1", 1001, int(stat.Ino))
	ct.writeProcNetSocktabWithPid("tcp", 1001, int(containerNetNS1tcp))
	ct.writeProcNetSocktabWithPid("tcp6", 1001, int(containerNetNS1tcp6))
	ct.writeProcNetSocktabWithPid("udp", 1001, int(containerNetNS1udp))
	ct.writeProcNetSocktabWithPid("udp6", 1001, int(containerNetNS1udp6))
	ct.writeProcNetSocktabWithPid("udplite", 1001, int(containerNetNS1udplite))
	ct.writeProcNetSocktabWithPid("udplite6", 1001, int(containerNetNS1udplite6))
	ct.writeProcNetSocktabWithPid("raw", 1001, int(containerNetNS1raw))
	ct.writeProcNetSocktabWithPid("raw6", 1001, int(containerNetNS1raw6))
	ct.createNetNsContainer("testnsnet2", 1002, 12346)
	ct.writeProcNetSocktabWithPid("tcp", 1002, int(containerNetNS2tcp))
	ct.writeProcNetSocktabWithPid("tcp6", 1002, int(containerNetNS2tcp6))
	ct.writeProcNetSocktabWithPid("udp", 1002, int(containerNetNS2udp))
	ct.writeProcNetSocktabWithPid("udp6", 1002, int(containerNetNS2udp6))
	ct.writeProcNetSocktabWithPid("udplite", 1002, int(containerNetNS2udplite))
	ct.writeProcNetSocktabWithPid("udplite6", 1002, int(containerNetNS2udplite6))
	ct.writeProcNetSocktabWithPid("raw", 1002, int(containerNetNS2raw))
	ct.writeProcNetSocktabWithPid("raw6", 1002, int(containerNetNS2raw6))
	ct.createProcess(784045, 999, "testingtesting")
}

func (ct *commontests) Close() {
	err := os.RemoveAll(ct.procTmpDir)
	if err != nil {
		panic(err)
	}

	err = os.RemoveAll(ct.netNsPathTmpDir)
	if err != nil {
		panic(err)
	}
}

func TestNetstat(t *testing.T) {
	ct := commontests{}
	ct.setupMock()
	defer ct.Close()

	t.Run("test all sockets", func(t *testing.T) {
		feature := netstat.EnableFeatures{
			TCP:      true,
			TCP6:     true,
			UDP:      true,
			UDP6:     true,
			UDPLite:  true,
			UDPLite6: true,
			Raw:      true,
			Raw6:     true,
		}
		testResult, err := netstat.Netstat(context.TODO(), feature, netstat.NoopFilter)
		if err != nil {
			t.Fatalf("Netstat returned error: %v", err)
		}
		expectedCount := int(tcp + tcp6 + udp + udp6 + udplite + udplite6 + raw + raw6)
		if len(testResult) != expectedCount {
			t.Fatalf("Expected %d sockets, got %d", expectedCount, len(testResult))
		}
	})

	t.Run("test all sockets with no host network", func(t *testing.T) {
		feature := netstat.EnableFeatures{
			NoHostNetwork: true,
			TCP:           true,
			TCP6:          true,
			UDP:           true,
			UDP6:          true,
			UDPLite:       true,
			UDPLite6:      true,
			Raw:           true,
			Raw6:          true,
		}
		testResult, err := netstat.Netstat(context.TODO(), feature, netstat.NoopFilter)
		if err != nil {
			t.Fatalf("Netstat returned error: %v", err)
		}
		expectedCount := 0
		if len(testResult) != expectedCount {
			t.Fatalf("Expected %d sockets, got %d", expectedCount, len(testResult))
		}
	})

	t.Run("test all sockets for a single namespace", func(t *testing.T) {
		feature := netstat.EnableFeatures{
			NetNsName:     []string{"testnsnet1"},
			TCP:           true,
			TCP6:          true,
			UDP:           true,
			UDP6:          true,
			UDPLite:       true,
			UDPLite6:      true,
			Raw:           true,
			Raw6:          true,
			NoHostNetwork: true,
		}
		testResult, err := netstat.Netstat(context.TODO(), feature, netstat.NoopFilter)
		if err != nil {
			t.Fatalf("Netstat returned error: %v", err)
		}
		expectedCount := int(containerNetNS1tcp + containerNetNS1tcp6 + containerNetNS1udp + containerNetNS1udp6 + containerNetNS1udplite + containerNetNS1udplite6 + containerNetNS1raw + containerNetNS1raw6)
		if len(testResult) != expectedCount {
			t.Fatalf("Expected %d sockets, got %d", expectedCount, len(testResult))
		}
	})

	t.Run("test all sockets for a single + host namespace and protocol", func(t *testing.T) {
		feature := netstat.EnableFeatures{
			NetNsName: []string{"testnsnet1"},
			TCP:       true,
		}
		testResult, err := netstat.Netstat(context.TODO(), feature, netstat.NoopFilter)
		if err != nil {
			t.Fatalf("Netstat returned error: %v", err)
		}
		expectedCount := int(containerNetNS1tcp) + int(tcp)
		if len(testResult) != expectedCount {
			t.Fatalf("Expected %d sockets, got %d", expectedCount, len(testResult))
		}
	})

	t.Run("test all sockets for a single + host namespace using Pids and protocol", func(t *testing.T) {
		feature := netstat.EnableFeatures{
			NetNsPids: []uint32{1001},
			TCP:       true,
		}
		testResult, err := netstat.Netstat(context.TODO(), feature, netstat.NoopFilter)
		if err != nil {
			t.Fatalf("Netstat returned error: %v", err)
		}
		expectedCount := int(containerNetNS1tcp) + int(tcp)
		if len(testResult) != expectedCount {
			t.Fatalf("Expected %d sockets, got %d", expectedCount, len(testResult))
		}
	})

	t.Run("test all sockets for a single namespace with PID enabled", func(t *testing.T) {
		feature := netstat.EnableFeatures{
			NetNsName:     []string{"testnsnet1"},
			TCP:           true,
			TCP6:          true,
			UDP:           true,
			UDP6:          true,
			UDPLite:       true,
			UDPLite6:      true,
			Raw:           true,
			Raw6:          true,
			NoHostNetwork: true,
			PID:           true,
		}
		testResult, err := netstat.Netstat(context.TODO(), feature, netstat.NoopFilter)
		if err != nil {
			t.Fatalf("Netstat returned error: %v", err)
		}
		expectedCount := int(containerNetNS1tcp + containerNetNS1tcp6 + containerNetNS1udp + containerNetNS1udp6 + containerNetNS1udplite + containerNetNS1udplite6 + containerNetNS1raw + containerNetNS1raw6)
		if len(testResult) != expectedCount {
			t.Fatalf("Expected %d sockets, got %d", expectedCount, len(testResult))
		}
		for _, socket := range testResult {
			if socket.Process.Pid == 0 {
				t.Fatalf("Expected PID to be non-zero, got %d", socket.Process.Pid)
			}
		}
	})

	t.Run("test all sockets for all available namespaces", func(t *testing.T) {
		feature := netstat.EnableFeatures{
			TCP:           true,
			TCP6:          true,
			UDP:           true,
			UDP6:          true,
			UDPLite:       true,
			UDPLite6:      true,
			Raw:           true,
			Raw6:          true,
			NoHostNetwork: true,
			AllNetNs:      true,
		}
		testResult, err := netstat.Netstat(context.TODO(), feature, netstat.NoopFilter)
		if err != nil {
			t.Fatalf("Netstat returned error: %v", err)
		}
		expectedCount := int(containerNetNS1tcp + containerNetNS1tcp6 + containerNetNS1udp + containerNetNS1udp6 + containerNetNS1udplite + containerNetNS1udplite6 + containerNetNS1raw + containerNetNS1raw6)
		if len(testResult) != expectedCount {
			t.Fatalf("Expected %d sockets, got %d", expectedCount, len(testResult))
		}
	})
}
