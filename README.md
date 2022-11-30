###  To avoid high CPU usage on Linux and on Window, this fork avoids costly process info extraction if AcceptFn calculated sockets count internally and returned false for each socket.

```
Usage of ./go-netstat:
  -4    display only IPv4 sockets
  -6    display only IPv6 sockets
  -all
    	display both listening and non-listening sockets
  -help
    	display this help screen
  -lis
    	display only listening sockets
  -res
        lookup symbolic names for host addresses
  -tcp
    	display TCP sockets
  -udp
    	display UDP sockets
```
### Installation:

```
$ go get github.com/sokurenko/go-netstat
```

### Using as a library
#### [Godoc](https://godoc.org/github.com/cakturk/go-netstat/netstat)
#### Getting the package
```
$ go mod init tcp_count
$ go mod tidy
$ go run tcp_count.go
```

```go
package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/sokurenko/go-netstat/netstat"
)

func netStatTcpCount(laddres net.IP, lNet *net.IPNet, lport int, raddres net.IP, rNet *net.IPNet, rport int,
	state netstat.SkState) (result int, err error) {
	count := 0

	_, err = netstat.TCPSocks(func(s *netstat.SockTabEntry) bool {
		if state != 0 && s.State != state {
			return false
		}
		if lport != 0 && s.LocalAddr.Port != uint16(lport) {
			return false
		}
		if laddres != nil && !s.LocalAddr.IP.Equal(laddres) {
			return false
		}
		if lNet != nil && !lNet.Contains(s.LocalAddr.IP) {
			return false
		}
		if rport != 0 && s.RemoteAddr.Port != uint16(rport) {
			return false
		}
		if raddres != nil && !s.RemoteAddr.IP.Equal(raddres) {
			return false
		}
		if rNet != nil && !rNet.Contains(s.RemoteAddr.IP) {
			return false
		}

		count++
		return false
	})
	if err != nil {
		return 0, err
	}

	_, err = netstat.TCP6Socks(func(s *netstat.SockTabEntry) bool {
		if state != 0 && s.State != state {
			return false
		}
		if lport != 0 && s.LocalAddr.Port != uint16(lport) {
			return false
		}
		if laddres != nil && !s.LocalAddr.IP.Equal(laddres) {
			return false
		}
		if lNet != nil && !lNet.Contains(s.LocalAddr.IP) {
			return false
		}
		if rport != 0 && s.RemoteAddr.Port != uint16(rport) {
			return false
		}
		if raddres != nil && !s.RemoteAddr.IP.Equal(raddres) {
			return false
		}
		if rNet != nil && !rNet.Contains(s.RemoteAddr.IP) {
			return false
		}
		count++
		return false
	})

	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}

	return count, nil
}

func main() {
	count, err := netStatTcpCount(nil, nil, 0, nil, nil, 0, netstat.Listen)
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println("count:", count)
}
```
