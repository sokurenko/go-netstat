// Package netstat provides primitives for getting socket information on a
// Linux based operating system.
package netstat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"sync"
)

const (
	pathTCPTab      = "/proc/net/tcp"
	pathTCP6Tab     = "/proc/net/tcp6"
	pathUDPTab      = "/proc/net/udp"
	pathUDP6Tab     = "/proc/net/udp6"
	pathUDPLiteTab  = "/proc/net/udplite"
	pathUDPLite6Tab = "/proc/net/udplite6"
	pathRawTab      = "/proc/net/raw"
	pathRaw6Tab     = "/proc/net/raw6"

	ipv4StrLen = 8
	ipv6StrLen = 32
)

// Socket states
const (
	Established SkState = 0x01
	SynSent     SkState = 0x02
	SynRecv     SkState = 0x03
	FinWait1    SkState = 0x04
	FinWait2    SkState = 0x05
	TimeWait    SkState = 0x06
	Close       SkState = 0x07
	CloseWait   SkState = 0x08
	LastAck     SkState = 0x09
	Listen      SkState = 0x0a
	Closing     SkState = 0x0b
)

var skStates = [...]string{
	"UNKNOWN",
	"ESTABLISHED",
	"SYN_SENT",
	"SYN_RECV",
	"FIN_WAIT1",
	"FIN_WAIT2",
	"TIME_WAIT",
	"CLOSE",
	"CLOSE_WAIT",
	"LAST_ACK",
	"LISTEN",
	"CLOSING",
}

// socket timer states
const (
	Off           TimerActive = 0x00
	On            TimerActive = 0x01
	KeepAlive     TimerActive = 0x02
	TimeWaitTimer TimerActive = 0x03 // Unsure how to call this
	ProbeTimer    TimerActive = 0x04 // Unsure how to call this
)

var TimerActives = [...]string{
	"Off",
	"On",
	"KeepAlive",
	"TimeWait",   // Unsure how to call this
	"ProbeTimer", // Unsure how to call this
}

// Errors returned by gonetstat
var (
	ErrNotEnoughFields = errors.New("gonetstat: not enough fields in the line")
)

func parseIPv4(s string) (net.IP, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}
	ip := make(net.IP, net.IPv4len)
	binary.LittleEndian.PutUint32(ip, uint32(v))
	return ip, nil
}

func parseIPv6(s string) (net.IP, error) {
	ip := make(net.IP, net.IPv6len)
	const grpLen = 4
	i, j := 0, 4
	for len(s) != 0 {
		grp := s[0:8]
		u, err := strconv.ParseUint(grp, 16, 32)
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(ip[i:j], uint32(u))
		i, j = i+grpLen, j+grpLen
		s = s[8:]
	}
	return ip, nil
}

func parseAddr(s string) (*SockEndpoint, error) {
	fields := strings.Split(s, ":")
	if len(fields) < 2 {
		return nil, fmt.Errorf("netstat: not enough fields: %v", s)
	}
	var ip net.IP
	var err error
	switch len(fields[0]) {
	case ipv4StrLen:
		ip, err = parseIPv4(fields[0])
	case ipv6StrLen:
		ip, err = parseIPv6(fields[0])
	default:
		err = fmt.Errorf("netstat: bad formatted string: %v", fields[0])
	}
	if err != nil {
		return nil, err
	}
	v, err := strconv.ParseUint(fields[1], 16, 16)
	if err != nil {
		return nil, err
	}
	return &SockEndpoint{IP: ip, Port: uint16(v)}, nil
}

func parseSockTab(reader io.Reader, accept AcceptFn, transport string) ([]SockTabEntry, error) {
	scanner := bufio.NewScanner(reader)
	scanner.Scan()

	var sockTab []SockTabEntry
	for scanner.Scan() {
		line := scanner.Text()
		var entry SockTabEntry
		var localEndpoint, remoteEndpoint string
		var index int64
		_, err := fmt.Sscanf(line, "%d: %s %s %X %X:%X %d:%X %X %d %d %d %d %X",
			&index,
			&localEndpoint,
			&remoteEndpoint,
			&entry.State,
			&entry.TxQueue,
			&entry.RxQueue,
			&entry.Tr,
			&entry.TimerWhen,
			&entry.Retrnsmt,
			&entry.UID,
			&entry.Timeout,
			&entry.Inode,
			&entry.Ref,
			&entry.Pointer,
		)
		if err != nil {
			return nil, err
		}

		entry.LocalEndpoint, err = parseAddr(localEndpoint)
		if err != nil {
			return nil, err
		}
		entry.RemoteEndpoint, err = parseAddr(remoteEndpoint)
		if err != nil {
			return nil, err
		}
		entry.Transport = transport
		if accept(&entry) {
			sockTab = append(sockTab, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return sockTab, nil
}

type procFd struct {
	base  string
	pid   int
	sktab []SockTabEntry
	p     *Process
}

const sockPrefix = "socket:["

func getProcName(s []byte) string {
	i := bytes.Index(s, []byte("("))
	if i < 0 {
		return ""
	}
	j := bytes.LastIndex(s, []byte(")"))
	if j < 1 || i+1 >= j {
		return ""
	}
	return string(s[i+1 : j])
}

var processCache sync.Map

func (p *procFd) getProcess() (*Process, error) {
	cached, ok := processCache.Load(p.base)
	if ok {
		return cached.(*Process), nil
	}

	stat, err := os.Open(path.Join(p.base, "stat"))
	if err != nil {
		return nil, err
	}
	defer stat.Close()

	var buf [1024]byte
	n, err := stat.Read(buf[:])
	if err != nil {
		return nil, err
	}
	z := bytes.SplitN(buf[:n], []byte(" "), 3)
	name := getProcName(z[1])
	process := &Process{p.pid, name}

	processCache.Store(p.base, process)

	return process, nil
}

func (p *procFd) iterFdDir() {
	// link Name is of the form socket:[5860846]
	fddir := path.Join(p.base, "/fd")
	fi, err := os.ReadDir(fddir)
	if err != nil {
		return
	}

	for _, file := range fi {
		fd := path.Join(fddir, file.Name())
		lname, err := os.Readlink(fd)
		if err != nil || !strings.HasPrefix(lname, sockPrefix) {
			continue
		}
		for i := range p.sktab {
			sk := &p.sktab[i]
			ss := sockPrefix + strconv.FormatUint(sk.Inode, 10) + "]"
			if ss != lname {
				continue
			}
			if p.p == nil {
				p.p, _ = p.getProcess()
			}
			sk.Process = p.p
		}
	}
}

func extractProcInfo(sktab []SockTabEntry) {
	const basedir = "/proc"
	fi, err := os.ReadDir(basedir)
	if err != nil {
		return
	}

	// Create a channel to send PIDs to worker goroutines.
	pidCh := make(chan int, len(fi))

	// Create a wait group to wait for all worker goroutines to finish.
	var wg sync.WaitGroup
	wg.Add(runtime.NumCPU())

	// Start worker goroutines.
	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			defer wg.Done()
			for pid := range pidCh {
				base := path.Join(basedir, strconv.Itoa(pid))
				proc := procFd{base: base, pid: pid, sktab: sktab}
				proc.iterFdDir()
			}
		}()
	}

	// Send PIDs to worker goroutines.
	for _, file := range fi {
		if !file.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(file.Name())
		if err != nil {
			continue
		}
		pidCh <- pid
	}

	// Close the PID channel to signal to worker goroutines that no more PIDs will be sent.
	close(pidCh)

	// Wait for all worker goroutines to finish.
	wg.Wait()
}

func procFiles(feature EnableFeatures) []string {
	var files []string
	if feature.TCP {
		files = append(files, pathTCPTab)
	}
	if feature.TCP6 {
		files = append(files, pathTCP6Tab)
	}
	if feature.UDP {
		files = append(files, pathUDPTab)
	}
	if feature.UDP6 {
		files = append(files, pathUDP6Tab)
	}
	if feature.UDPLite {
		files = append(files, pathUDPLiteTab)
	}
	if feature.UDPLite6 {
		files = append(files, pathUDPLite6Tab)
	}
	if feature.Raw {
		files = append(files, pathRawTab)
	}
	if feature.Raw6 {
		files = append(files, pathRaw6Tab)
	}
	return files
}

// Netstat - collect information about network port status
func Netstat(ctx context.Context, feature EnableFeatures, fn AcceptFn) ([]SockTabEntry, error) {
	files := procFiles(feature)
	// Create a channel for each file to receive its results.
	chs := make([]chan []SockTabEntry, len(files))
	for i := range chs {
		chs[i] = make(chan []SockTabEntry)
	}

	// Launch a goroutine for each file.
	for i, file := range files {
		go func(i int, file string) {
			select {
			case <-ctx.Done():
				// If the context is cancelled, send an empty slice and return.
				chs[i] <- []SockTabEntry{}
				return
			default:
				tabs, err := openFileStream(file, fn)
				if err != nil {
					// Send an empty slice if there was an error.
					chs[i] <- []SockTabEntry{}
					return
				}
				chs[i] <- tabs
			}
		}(i, file)
	}

	// Collect the results from each channel in order and append them to combinedTabs.
	var combinedTabs []SockTabEntry
	for _, ch := range chs {
		select {
		case <-ctx.Done():
			// If the context is cancelled, return immediately with the current result.
			return combinedTabs, ctx.Err()
		case tabs := <-ch:
			combinedTabs = append(combinedTabs, tabs...)
		}
	}

	if feature.PID && len(combinedTabs) != 0 {
		extractProcInfo(combinedTabs)
	}

	return combinedTabs, nil
}

func openFileStream(file string, fn AcceptFn) ([]SockTabEntry, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	transport := file[strings.LastIndex(file, "/")+1:]
	tabs, err := parseSockTab(f, fn, transport)
	if err != nil {
		return nil, err
	}
	return tabs, nil
}
