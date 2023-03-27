package netstat

import (
	"fmt"
	"net"

	"github.com/nberlee/go-netstat/common"
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
	Process *common.Process
	NetNS   string
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
	// TCP sockets and connections
	TCP bool
	// TCP6 (ipv6) sockets and connections
	TCP6 bool
	// UDP sockets and connections
	UDP bool
	// UDP6 (ipv6) sockets and connections
	UDP6 bool
	// UDP-Lite sockets and connections
	UDPLite bool
	// UDP-Lite6 (ipv6) sockets and connections
	UDPLite6 bool
	// Raw sockets and connections
	Raw bool
	// Raw6 (ipv6) sockets and connections
	Raw6 bool
	// Processes and Programs using sockets
	PID bool
	// Disable host network namespace
	NoHostNetwork bool
	// All network namespaces
	AllNetNs bool
	// Network namespace names using sockets and connections
	NetNsName []string
	// Network namespace PIDs using sockets and connections
	NetNsPids []uint32
}
