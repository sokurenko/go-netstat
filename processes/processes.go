package processes

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"

	"github.com/nberlee/go-netstat/common"
)

const (
	sockPrefix = "socket:["
)

func getProcName(s []byte) string {
	start := bytes.IndexByte(s, '(')
	if start < 0 {
		return ""
	}
	end := bytes.IndexByte(s[start:], ')')
	if end < 1 {
		return ""
	}
	return string(s[start+1 : start+end])
}

func GetProcessFDs(ctx context.Context) (processFDs map[uint64]*common.Process, procErr error) {
	processFDs = make(map[uint64]*common.Process)
	processCache := sync.Map{}

	procs, err := os.ReadDir(common.ProcPath)
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, proc := range procs {
		wg.Add(1)
		go func(proc fs.DirEntry) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			default:
				pid, err := strconv.Atoi(proc.Name())
				if err != nil {
					return
				}

				fdPath := fmt.Sprintf("%s/%d/fd", common.ProcPath, pid)
				entries, err := os.ReadDir(fdPath)
				if err != nil {
					return
				}
				for _, entry := range entries {
					link, err := os.Readlink(path.Join(fdPath, entry.Name()))
					if err != nil {
						continue
					}
					if !strings.HasPrefix(link, sockPrefix) {
						continue
					}

					fd, err := strconv.ParseUint(link[8:len(link)-1], 10, 64)
					if err != nil {
						continue
					}

					process, err := getProcess(pid, &processCache)
					if err != nil {
						process = &common.Process{Pid: pid}
					}

					mu.Lock()
					processFDs[fd] = process
					mu.Unlock()
				}
			}
		}(proc)
	}

	wg.Wait()

	return processFDs, procErr
}

func getProcess(pid int, processCache *sync.Map) (*common.Process, error) {
	cached, ok := processCache.Load(pid)
	if ok {
		return cached.(*common.Process), nil
	}

	base := path.Join(common.ProcPath, strconv.Itoa(pid))
	stat, err := os.ReadFile(path.Join(base, "stat"))
	if err != nil {
		return &common.Process{Pid: pid}, err
	}

	var name string
	z := bytes.SplitN(stat, []byte(" "), 3)
	name = getProcName(z[1])
	process := &common.Process{Pid: pid, Name: name}

	processCache.Store(pid, process)

	return process, nil
}
