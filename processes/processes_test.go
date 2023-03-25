package processes_test

import (
	"context"
	"fmt"
	"os"
	"path"
	"reflect"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/nberlee/go-netstat/common"
	"github.com/nberlee/go-netstat/processes"
)

func TestGetProcName(t *testing.T) {
	testCases := []struct {
		input    []byte
		expected string
	}{
		{
			input:    []byte("(vivaldi-bin)"),
			expected: "vivaldi-bin",
		},
		{
			input:    []byte(" (vivaldi-bin)"),
			expected: "vivaldi-bin",
		},
		{
			input:    []byte("160006 (vivaldi-bin)"),
			expected: "vivaldi-bin",
		},
		{
			input:    []byte("0 (v)"),
			expected: "v",
		},
		{
			input:    []byte("160006 )vivaldi-bin("),
			expected: "",
		},
		{
			input:    []byte("160006 )vivaldi-bin"),
			expected: "",
		},
		{
			input:    []byte("160006 (vivaldi-bin"),
			expected: "",
		},
		{
			input:    []byte("160006 ()"),
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("Input: %s", tc.input), func(t *testing.T) {
			result := processes.GetProcName(tc.input)
			if result != tc.expected {
				t.Errorf("Expected result to be %s, but got %s", tc.expected, result)
			}
		})
	}
}
func TestGetProcess(t *testing.T) {
	// Create a temporary process directory
	tmpProcPath, err := os.MkdirTemp("", "mock_proc_")
	if err != nil {
		t.Fatalf("Failed to create temporary process directory: %v", err)
	}
	defer os.RemoveAll(tmpProcPath)

	// Create a mocked process stat file
	mockPid := 12345
	mockProcessName := "testproc"
	statContent := []byte(fmt.Sprintf("%d (%s) R 1 1 1 0 -1 4194560", mockPid, mockProcessName))
	err = os.Mkdir(path.Join(tmpProcPath, strconv.Itoa(mockPid)), 0755)
	if err != nil {
		t.Fatalf("Failed to create temporary pid directory: %v", err)
	}
	err = os.WriteFile(path.Join(tmpProcPath, strconv.Itoa(mockPid), "stat"), statContent, 0644)
	if err != nil {
		t.Fatalf("Failed to create temporary stat file: %v", err)
	}

	// Temporarily replace the common.ProcPath global variable
	oldProcPath := common.ProcPath
	common.ProcPath = tmpProcPath
	defer func() { common.ProcPath = oldProcPath }()

	// Test scenarios
	tests := []struct {
		name        string
		pid         int
		wantProcess *common.Process
		wantErr     bool
	}{
		{
			name: "existing_process",
			pid:  mockPid,
			wantProcess: &common.Process{
				Pid:  mockPid,
				Name: mockProcessName,
			},
			wantErr: false,
		},
		{
			name:        "non_existing_process",
			pid:         99999,
			wantProcess: &common.Process{Pid: 99999},
			wantErr:     true,
		},
	}

	processCache := &sync.Map{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			process, err := processes.GetProcess(tt.pid, processCache)

			if (err != nil) != tt.wantErr {
				t.Fatalf("getProcess() returned unexpected error status: got %v, want %v", err, tt.wantErr)
			}

			if !reflect.DeepEqual(process, tt.wantProcess) {
				t.Errorf("getProcess() returned unexpected process: got %v, want %v", process, tt.wantProcess)
			}
		})
	}
}

func createTempProcStructure(tempDir string) error {
	// Create directories for mocked PIDs
	pidDirs := []string{"1", "2"}

	for _, pid := range pidDirs {
		pidPath := path.Join(tempDir, pid)
		err := os.Mkdir(pidPath, 0755)
		if err != nil {
			return err
		}

		fdPath := path.Join(pidPath, "fd")
		err = os.Mkdir(fdPath, 0755)
		if err != nil {
			return err
		}

		// Create mocked fd symlinks
		// Create mocked fd symlinks
		if pid == "1" {
			fdLink := "socket:[12345]"
			fd := path.Join(fdPath, "0")
			err = os.Symlink(fdLink, fd)
			if err != nil {
				return err
			}
		} else if pid == "2" {
			fdLink := "socket:[67890]"
			fd := path.Join(fdPath, "0")
			err = os.Symlink(fdLink, fd)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func TestGetProcessFDs(t *testing.T) {
	// Create a temporary directory
	tempDir, err := os.MkdirTemp("", "proc")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create temporary proc structure
	err = createTempProcStructure(tempDir)
	if err != nil {
		t.Fatalf("Failed to create temp proc structure: %v", err)
	}

	// Override common.ProcPath with the temporary directory path
	common.ProcPath = tempDir

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	processFDs, procErr := processes.GetProcessFDs(ctx)
	if procErr != nil {
		t.Errorf("Unexpected error: %v", procErr)
	}

	expectedFDs := map[uint64]*common.Process{
		12345: {Pid: 1},
		67890: {Pid: 2},
	}

	if len(expectedFDs) != len(processFDs) {
		t.Errorf("Expected %d FDs, got %d", len(expectedFDs), len(processFDs))
	}

	for fd, expectedProcess := range expectedFDs {
		actualProcess, ok := processFDs[fd]
		if !ok {
			t.Errorf("Expected FD %d not found", fd)
		} else if expectedProcess.Pid != actualProcess.Pid {
			t.Errorf("Expected pid %d for FD %d, got %d", expectedProcess.Pid, fd, actualProcess.Pid)
		}
	}
}
