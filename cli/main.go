package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"strings"

	"github.com/nberlee/go-netstat/netstat"
)

var (
	listening = flag.Bool("l", false, "display listening server sockets")
	all       = flag.Bool("a", false, "display all sockets (default: connected)")
	numeric   = flag.Bool("n", true, "don't resolve names")
	ipv4      = flag.Bool("4", false, "display only IPv4 sockets")
	ipv6      = flag.Bool("6", false, "display only IPv6 sockets")
	pid       = flag.Bool("p", false, "display PID/Program name for sockets")
	tcp       = flag.Bool("t", false, "display tcp sockets")
	udp       = flag.Bool("u", false, "display udp sockets")
	udplite   = flag.Bool("U", false, "display udplite sockets")
	raw       = flag.Bool("w", false, "display raw sockets")

	help   = flag.Bool("help", false, "display this help screen")
	nsPids = flag.String("pids", "", "comma separated list of pids in different network namespaces")
)

func commaStringToUint32Array(s string) ([]uint32, error) {
	strValues := strings.Split(s, ",")
	uint32Values := make([]uint32, len(strValues))
	for i, strValue := range strValues {
		uint32Value, err := strconv.ParseUint(strValue, 10, 32)
		if err != nil {
			return nil, err
		}
		uint32Values[i] = uint32(uint32Value)
	}
	return uint32Values, nil
}

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	var features netstat.EnableFeatures

	if *tcp || *udp || *udplite || *raw {
		features.TCP = *tcp
		features.TCP6 = *tcp
		features.UDP = *udp
		features.UDP6 = *udp
		features.UDPLite = *udplite
		features.UDPLite6 = *udplite
		features.Raw = *raw
		features.Raw6 = *raw
	} else {
		// Nothing set, default behaviour
		features.TCP = true
		features.TCP6 = true
		features.UDP = true
		features.UDP6 = true
	}
	if *ipv4 && !*ipv6 {
		features.TCP6 = false
		features.UDP6 = false
		features.UDPLite6 = false
		features.Raw6 = false
	}
	if *ipv6 && !*ipv4 {
		features.TCP = false
		features.UDP = false
		features.UDPLite = false
		features.Raw = false
	}

	features.PID = *pid

	if *nsPids != "" {
		features.NsPids, _ = commaStringToUint32Array(*nsPids)
		if len(features.NsPids) == 1 {
			features.NoHostNetwork = true
		}
	}

	if os.Geteuid() != 0 {
		fmt.Println("Not all processes could be identified, you would have to be root to see it all.")
	}
	fmt.Printf("Proto %-23s %-23s %-12s %-16s %-6s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name", "nsNetPid")

	var fn netstat.AcceptFn

	switch {
	case *all:
		fn = func(*netstat.SockTabEntry) bool { return true }
	case *listening:
		fn = func(s *netstat.SockTabEntry) bool {
			return s.State == netstat.Listen
		}
	default:
		fn = func(s *netstat.SockTabEntry) bool {
			return s.State != netstat.Listen
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt)
		<-sig
		cancel()
	}()

	tabs, err := netstat.Netstat(ctx, features, fn)
	if err == nil {
		displaySockInfo(tabs)
	} else {
		fmt.Print(err)
	}

}

func displaySockInfo(s []netstat.SockTabEntry) {
	lookup := func(skaddr *netstat.SockEndpoint) string {
		const IPv4Strlen = 17
		addr := skaddr.IP.String()
		if !*numeric {
			names, err := net.LookupAddr(addr)
			if err == nil && len(names) > 0 {
				addr = names[0]
			}
		}
		if len(addr) > IPv4Strlen {
			addr = addr[:IPv4Strlen]
		}
		return fmt.Sprintf("%s:%d", addr, skaddr.Port)
	}

	for _, e := range s {
		p := ""
		if e.Process != nil {
			p = e.Process.String()
		}
		saddr := lookup(e.LocalEndpoint)
		daddr := lookup(e.RemoteEndpoint)
		fmt.Printf("%-5s %-23.23s %-23.23s %-12s %-16s %-6d\n", e.Transport, saddr, daddr, e.State, p, e.PodPid)
	}
}
