package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"

	"github.com/nberlee/go-netstat/netstat"
)

var (
	listening = flag.Bool("lis", false, "display only listening sockets")
	all       = flag.Bool("all", false, "display both listening and non-listening sockets")
	resolve   = flag.Bool("res", false, "lookup symbolic names for host addresses")
	ipv4      = flag.Bool("4", false, "display only IPv4 sockets")
	ipv6      = flag.Bool("6", false, "display only IPv6 sockets")
	help      = flag.Bool("help", false, "display this help screen")
)

const (
	protoIPv4 = 0x01
	protoIPv6 = 0x02
)

func main() {
	flag.Parse()

	if *help {
		flag.Usage()
		os.Exit(0)
	}

	var proto uint
	if *ipv4 {
		proto |= protoIPv4
	}
	if *ipv6 {
		proto |= protoIPv6
	}
	if proto == 0x00 {
		proto = protoIPv4 | protoIPv6
	}

	if os.Geteuid() != 0 {
		fmt.Println("Not all processes could be identified, you would have to be root to see it all.")
	}
	fmt.Printf("Proto %-23s %-23s %-12s %-16s\n", "Local Addr", "Foreign Addr", "State", "PID/Program name")

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
	if proto&protoIPv4 == protoIPv4 {
		tabs, err := netstat.Netstat(ctx, fn)
		if err == nil {
			displaySockInfo(tabs)
		} else {
			fmt.Print(err)
		}
	}

}

func displaySockInfo(s []netstat.SockTabEntry) {
	lookup := func(skaddr *netstat.SockEndpoint) string {
		const IPv4Strlen = 17
		addr := skaddr.IP.String()
		if *resolve {
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
		fmt.Printf("%-5s %-23.23s %-23.23s %-12s %-16s\n", e.Proto, saddr, daddr, e.State, p)
	}
}
