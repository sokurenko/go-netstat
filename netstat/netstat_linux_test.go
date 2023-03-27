package netstat_test

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/nberlee/go-netstat/netstat"
)

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		input string
		want  net.IP
		err   error
	}{
		{input: "0100007F", want: net.IPv4(127, 0, 0, 1), err: nil},
		{input: "0F00000A", want: net.IPv4(10, 0, 0, 15), err: nil},
		{input: "FFFFFFFF", want: net.IPv4(255, 255, 255, 255), err: nil},
		{input: "gibberish", want: nil, err: &strconv.NumError{Func: "ParseUint", Num: "gibberish", Err: strconv.ErrSyntax}},
	}

	for _, tc := range tests {
		got, err := netstat.ParseIPv4(tc.input)

		if !got.Equal(tc.want) {
			t.Errorf("parseIPv4(%s) = %s, want %s", tc.input, got, tc.want)
		}

		if err == nil && tc.err == nil {
			continue
		}

		if err == nil || tc.err == nil || err.Error() != tc.err.Error() {
			t.Errorf("parseIPv4(%s) returned error %v, want %v", tc.input, err, tc.err)
		}
	}
}

func TestParseIPv6(t *testing.T) {
	tests := []struct {
		input string
		want  net.IP
		err   error
	}{
		{input: "341280FE11107856FF015FE6C65847FE", want: net.ParseIP("fe80:1234:5678:1011:e65f:1ff:fe47:58c6"), err: nil},
		{input: "gibberish", want: nil, err: &strconv.NumError{Func: "ParseUint", Num: "gibberis", Err: strconv.ErrSyntax}},
	}

	for _, tc := range tests {
		got, err := netstat.ParseIPv6(tc.input)

		if !got.Equal(tc.want) {
			t.Errorf("parseIPv6(%s) = %s, want %s", tc.input, got, tc.want)
		}

		if err == nil && tc.err == nil {
			continue
		}

		if err == nil || tc.err == nil || err.Error() != tc.err.Error() {
			t.Errorf("parseIPv6(%s) returned error %v, want %v", tc.input, err, tc.err)
		}
	}
}

func TestParseAddr(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantIP   net.IP
		wantPort uint16
		err      error
	}{
		{
			name:     "valid IPv4 address + port",
			input:    "0100007F:0035",
			wantIP:   net.IPv4(127, 0, 0, 1),
			wantPort: 53,
		},

		{
			name:     "valid IPv6 address + port",
			input:    "341280FE11107856FF015FE6C65847FE:1090",
			wantIP:   net.ParseIP("fe80:1234:5678:1011:e65f:1ff:fe47:58c6"),
			wantPort: 4240,
		},
		{
			name:  "invalid string",
			input: "341280FE11107856FF015FE6C65847FE",
			err:   fmt.Errorf("netstat: not enough fields: 341280FE11107856FF015FE6C65847FE"),
		},
		{
			name:  "invalid string",
			input: "gibberish:1111",
			err:   fmt.Errorf("netstat: bad formatted string: %s", "gibberish"),
		},
		{
			name:  "invalid string",
			input: "0100007F:FFFF1",
			err:   fmt.Errorf("strconv.ParseUint: parsing \"%s\": %s", "FFFF1", "value out of range"),
		},
	}

	for _, tc := range tests {
		got, err := netstat.ParseAddr(tc.input)
		if err == nil && tc.err == nil {
			if !got.IP.Equal(tc.wantIP) {
				t.Errorf("parseAddr(%s) = %s, want %s", tc.input, got.IP, tc.wantIP)
			}
			if got.Port != tc.wantPort {
				t.Errorf("parseAddr(%s) = %d, want %d", tc.input, got.Port, tc.wantPort)
			}
		}
		if err == nil && tc.err == nil {
			continue
		}

		if err == nil || tc.err == nil || err.Error() != tc.err.Error() {
			t.Errorf("parseAddr%s) returned error %v, want %v", tc.input, err, tc.err)
		}
	}
}

func TestParseSockTab(t *testing.T) {
	testCases := []struct {
		name           string
		acceptFn       netstat.AcceptFn
		inputStr       string
		expectedResult []netstat.SockTabEntry
		expectedLen    int
		expectedError  error
	}{
		{
			name:     "No filter",
			acceptFn: netstat.NoopFilter,
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107869 1 ffff88022c1e7000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     1        0 351522 1 0000000000000000 100 0 0 10 0
`,
			expectedResult: []netstat.SockTabEntry{
				{
					LocalEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 5037,
					},
					RemoteEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 0,
					},
					State: 10,
					UID:   0,
				},
				{
					LocalEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 22,
					},
					RemoteEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 0,
					},
					State: 10,
					UID:   1,
				},
			},
			expectedLen: 2,
		},
		{
			name: "One Filtered",
			acceptFn: func(entry *netstat.SockTabEntry) bool {
				return entry.UID == 0
			},
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107869 1 ffff88022c1e7000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     1        0 351522 1 0000000000000000 100 0 0 10 0
`,
			expectedResult: []netstat.SockTabEntry{
				{
					LocalEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 5037,
					},
					RemoteEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 0,
					},
					State: 10,
					UID:   0,
				},
			},
			expectedLen: 1,
		},
		{
			name: "One Filtered",
			acceptFn: func(entry *netstat.SockTabEntry) bool {
				return entry.UID == 0
			},
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107869 1 ffff88022c1e7000 100 0 0 10 0
   1: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     1        0 351522 1 0000000000000000 100 0 0 10 0
`,
			expectedResult: []netstat.SockTabEntry{
				{
					LocalEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 5037,
					},
					RemoteEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 0,
					},
					State: 10,
					UID:   0,
				},
			},
			expectedLen: 1,
		},
		{
			name: "A comment with a line which has not all 12",
			acceptFn: func(entry *netstat.SockTabEntry) bool {
				return entry.UID == 0
			},
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
# test
   0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107869 1 
`,
			expectedResult: []netstat.SockTabEntry{},
			expectedLen:    0,
			expectedError:  fmt.Errorf("expected integer"),
		},
		{
			name: "Local Address failure",
			acceptFn: func(entry *netstat.SockTabEntry) bool {
				return entry.UID == 0
			},
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107869 1 ffff88022c1e7000 100 0 0 10 0
`,
			expectedResult: []netstat.SockTabEntry{},
			expectedLen:    0,
			expectedError:  fmt.Errorf("netstat: bad formatted string: %s", "0100007"),
		},
		{
			name: "Remote Address failure",
			acceptFn: func(entry *netstat.SockTabEntry) bool {
				return entry.UID == 0
			},
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:13AD 000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 107869 1 ffff88022c1e7000 100 0 0 10 0
`,
			expectedResult: []netstat.SockTabEntry{},
			expectedLen:    0,
			expectedError:  fmt.Errorf("netstat: bad formatted string: %s", "000000000"),
		},
		{
			name: "Wrong connection state",
			acceptFn: func(entry *netstat.SockTabEntry) bool {
				return entry.UID == 0
			},
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0100007F:13AD 00000000:0000 0G 00000000:00000000 00:00000000 00000000     0        0 107869 1 ffff88022c1e7000 100 0 0 10 0
`,
			expectedResult: []netstat.SockTabEntry{},
			expectedLen:    0,
			expectedError:  fmt.Errorf("expected space in input to match format"),
		},
		{
			name: "Wrong user",
			acceptFn: func(entry *netstat.SockTabEntry) bool {
				return entry.UID == 0
			},
			inputStr: `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     -1        0 107869 1 ffff88022c1e7000 100 0 0 10 0
`,
			expectedResult: []netstat.SockTabEntry{},
			expectedLen:    0,
			expectedError:  fmt.Errorf("expected integer"),
		},
		{
			name:     "No filter raw socket",
			acceptFn: netstat.NoopFilter,
			inputStr: `   sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops
			1: 00000000:0001 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4229902743 2 00000000c5c41b4f 0
		   17: 0100007F:0011 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 4229856103 2 00000000651d476d 0
`,
			expectedResult: []netstat.SockTabEntry{
				{
					LocalEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 1,
					},
					RemoteEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 0,
					},
					State: netstat.Close,
					UID:   0,
				},
				{
					LocalEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 17,
					},
					RemoteEndpoint: &netstat.SockEndpoint{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 0,
					},
					State: netstat.Close,
					UID:   0,
				},
			},
			expectedLen: 2,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// Convert the input string to an io.Reader
			inputReader := strings.NewReader(tc.inputStr)
			// Call the parseSocktab function and store the result
			result, err := netstat.ParseSockTab(inputReader, tc.acceptFn, "tcp", 1)

			// Check if the function call returned an error
			if err != nil && tc.expectedError == nil {
				t.Fatalf("Got unexpected error %v", err)
			}
			if err == nil && tc.expectedError != nil {
				t.Fatalf("Expected error, bot got none: %v", tc.expectedError)
			}
			if err != nil && tc.expectedError != nil {
				if err.Error() != tc.expectedError.Error() {
					t.Fatalf("expected error:\n%v\ngot error: \n%v", tc.expectedError, err)
				}
			}
			// Check if the result has the expected length

			if len(result) != tc.expectedLen {
				t.Fatalf("unexpected result length: got %v, expected %v", len(result), tc.expectedLen)
			}

			for i, entry := range result {
				if !entry.LocalEndpoint.IP.Equal(tc.expectedResult[i].LocalEndpoint.IP) {
					t.Errorf("unexpected local IP: got %v, expected %v", entry.LocalEndpoint.IP, tc.expectedResult[i].LocalEndpoint.IP)
				}

				if entry.LocalEndpoint.Port != tc.expectedResult[i].LocalEndpoint.Port {
					t.Errorf("unexpected local port: got %v, expected %v", entry.LocalEndpoint.Port, tc.expectedResult[i].LocalEndpoint.Port)
				}
				if !entry.RemoteEndpoint.IP.Equal(tc.expectedResult[i].RemoteEndpoint.IP) {
					t.Errorf("unexpected remote IP: got %v, expected %v", entry.RemoteEndpoint.IP, tc.expectedResult[i].RemoteEndpoint.IP)
				}

				if entry.RemoteEndpoint.Port != tc.expectedResult[i].RemoteEndpoint.Port {
					t.Errorf("unexpected remote port: got %v, expected %v", entry.RemoteEndpoint.Port, tc.expectedResult[i].RemoteEndpoint.Port)
				}

				if entry.State != tc.expectedResult[i].State {
					t.Errorf("unexpected state: got %v, expected %v", entry.State, tc.expectedResult[i].State)
				}

				if entry.UID != tc.expectedResult[i].UID {
					t.Errorf("unexpected UID: got %v, expected %v", entry.UID, tc.expectedResult[i].UID)
				}
			}
		})
	}
}
