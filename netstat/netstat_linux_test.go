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
			result := netstat.GetProcName(tc.input)
			if result != tc.expected {
				t.Errorf("Expected result to be %s, but got %s", tc.expected, result)
			}
		})
	}
}

func TestParseSocktab(t *testing.T) {
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
					LocalAddr: &netstat.SockAddr{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 5037,
					},
					RemoteAddr: &netstat.SockAddr{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 0,
					},
					State: 10,
					UID:   0,
				},
				{
					LocalAddr: &netstat.SockAddr{
						IP:   net.ParseIP("0.0.0.0"),
						Port: 22,
					},
					RemoteAddr: &netstat.SockAddr{
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
					LocalAddr: &netstat.SockAddr{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 5037,
					},
					RemoteAddr: &netstat.SockAddr{
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
					LocalAddr: &netstat.SockAddr{
						IP:   net.ParseIP("127.0.0.1"),
						Port: 5037,
					},
					RemoteAddr: &netstat.SockAddr{
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
			expectedError:  fmt.Errorf("netstat: not enough fields: %d, [%s]", 11, "0: 0100007F:13AD 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 107869 1"),
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
			expectedError:  fmt.Errorf("strconv.ParseUint: parsing \"%s\": %v", "0G", strconv.ErrSyntax),
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
			expectedError:  fmt.Errorf("strconv.ParseUint: parsing \"%s\": %v", "-1", strconv.ErrSyntax),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// Convert the input string to an io.Reader
			inputReader := strings.NewReader(tc.inputStr)
			// Call the parseSocktab function and store the result
			result, err := netstat.ParseSocktab(inputReader, tc.acceptFn, "tcp")

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
				if !entry.LocalAddr.IP.Equal(tc.expectedResult[i].LocalAddr.IP) {
					t.Errorf("unexpected local IP: got %v, expected %v", entry.LocalAddr.IP, tc.expectedResult[i].LocalAddr.IP)
				}

				if entry.LocalAddr.Port != tc.expectedResult[i].LocalAddr.Port {
					t.Errorf("unexpected local port: got %v, expected %v", entry.LocalAddr.Port, tc.expectedResult[i].LocalAddr.Port)
				}
				if !entry.RemoteAddr.IP.Equal(tc.expectedResult[i].RemoteAddr.IP) {
					t.Errorf("unexpected remote IP: got %v, expected %v", entry.RemoteAddr.IP, tc.expectedResult[i].RemoteAddr.IP)
				}

				if entry.RemoteAddr.Port != tc.expectedResult[i].RemoteAddr.Port {
					t.Errorf("unexpected remote port: got %v, expected %v", entry.RemoteAddr.Port, tc.expectedResult[i].RemoteAddr.Port)
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
