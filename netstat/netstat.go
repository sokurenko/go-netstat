package netstat

import (
	"fmt"
	"net"
)

// SockEndpoint represents an ip:port pair
type SockEndpoint struct {
	IP   net.IP
	Port uint16
}

func (s *SockEndpoint) String() string {
	return fmt.Sprintf("%v:%d", s.IP, s.Port)
}

// SockTabEntry type represents each line of the /proc/net/[tcp|udp]
// Kernel >=5.15
type SockTabEntry struct {
	// Layer4 protocol, tcp, tcp6, udp or udp6
	Transport string
	// Local IPv4 address + Port
	LocalEndpoint *SockEndpoint
	// Remote IPv4 address + Port
	RemoteEndpoint *SockEndpoint
	// connection state
	State SkState
	// transmit-queue
	TxQueue uint64
	// receive-queue
	RxQueue uint64
	// timer_active
	Tr TimerActive
	// number of jiffies until timer expires
	TimerWhen uint64
	// number of unrecovered RTO Retransmission Timeouts
	Retrnsmt uint64
	// user ID
	UID uint32
	// unanswered 0-window probes
	Timeout uint64
	// inode
	Inode uint64
	// socket reference count
	Ref uint64
	// location of socket in memory
	Pointer uint64
	Process *Process
	PodPid  uint32
}

// Process holds the PID and process Name to which each socket belongs
type Process struct {
	Pid  int
	Name string
}

func (p *Process) String() string {
	return fmt.Sprintf("%d/%s", p.Pid, p.Name)
}

// SkState type represents socket connection state
type SkState uint8

func (s SkState) String() string {
	return skStates[s]
}

// TimerActive represents the state of the socket timer
type TimerActive uint8

func (t TimerActive) String() string {
	return TimerActives[t]
}

// AcceptFn is used to filter socket entries. The value returned indicates
// whether the element is to be appended to the socket list.
type AcceptFn func(*SockTabEntry) bool

// NoopFilter - a test function returning true for all elements
func NoopFilter(*SockTabEntry) bool { return true }

type EnableFeatures struct {
	TCP           bool
	TCP6          bool
	UDP           bool
	UDP6          bool
	UDPLite       bool
	UDPLite6      bool
	Raw           bool
	Raw6          bool
	PID           bool
	NoHostNetwork bool
	NsPids        []uint32
}
