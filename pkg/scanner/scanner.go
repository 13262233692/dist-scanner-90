package scanner

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"runtime"
	"sync"
	"time"
)

const (
	ScanModeAuto       = "auto"
	ScanModeTCPConnect = "tcp-connect"
	ScanModeSYN        = "syn"
	ScanModeSYNFragment = "syn-fragment"
)

type ScanResult struct {
	IP        string
	Port      int
	Open      bool
	LatencyMs int64
	Mode      string
}

type ScanConfig struct {
	Timeout        time.Duration
	RateLimit      int
	Mode           string
	SourceIP       string
	EnableFragment bool
	FragmentSize   int
}

type SYNScanner struct {
	config      ScanConfig
	hasRawSock  bool
	rawSockErr  string
}

func NewSYNScanner(timeout time.Duration, rateLimit int) *SYNScanner {
	return NewSYNScannerWithConfig(ScanConfig{
		Timeout:   timeout,
		RateLimit: rateLimit,
		Mode:      ScanModeAuto,
	})
}

func NewSYNScannerWithConfig(config ScanConfig) *SYNScanner {
	if config.Mode == "" {
		config.Mode = ScanModeAuto
	}
	if config.FragmentSize <= 0 {
		config.FragmentSize = 8
	}

	s := &SYNScanner{
		config: config,
	}

	if runtime.GOOS == "linux" && (config.Mode == ScanModeSYN || config.Mode == ScanModeSYNFragment || config.Mode == ScanModeAuto) {
		s.checkRawSocketSupport()
	}

	return s
}

func (s *SYNScanner) checkRawSocketSupport() {
	s.hasRawSock = false
	s.rawSockErr = "raw socket requires root privileges on Linux"
}

func (s *SYNScanner) Scan(ip string, port int) (*ScanResult, error) {
	start := time.Now()

	mode := s.config.Mode
	var open bool
	var err error
	var usedMode string

	switch mode {
	case ScanModeSYN:
		open, err = s.synScan(ip, port)
		usedMode = ScanModeSYN
		if err != nil {
			open, err = s.tcpConnectScan(ip, port)
			usedMode = ScanModeTCPConnect
		}

	case ScanModeSYNFragment:
		open, err = s.synFragmentScan(ip, port)
		usedMode = ScanModeSYNFragment
		if err != nil {
			open, err = s.tcpConnectScan(ip, port)
			usedMode = ScanModeTCPConnect
		}

	case ScanModeTCPConnect:
		open, err = s.tcpConnectScan(ip, port)
		usedMode = ScanModeTCPConnect

	default:
		if s.hasRawSock {
			if s.config.EnableFragment {
				open, err = s.synFragmentScan(ip, port)
				usedMode = ScanModeSYNFragment
			} else {
				open, err = s.synScan(ip, port)
				usedMode = ScanModeSYN
			}
			if err != nil {
				open, err = s.tcpConnectScan(ip, port)
				usedMode = ScanModeTCPConnect
			}
		} else {
			open, err = s.tcpConnectScan(ip, port)
			usedMode = ScanModeTCPConnect
		}
	}

	return &ScanResult{
		IP:        ip,
		Port:      port,
		Open:      open,
		LatencyMs: time.Since(start).Milliseconds(),
		Mode:      usedMode,
	}, err
}

func (s *SYNScanner) ScanRange(ipStart, ipEnd string, portStart, portEnd int, concurrency int) ([]*ScanResult, error) {
	startUint, err := ipToUint32(ipStart)
	if err != nil {
		return nil, err
	}
	endUint, err := ipToUint32(ipEnd)
	if err != nil {
		return nil, err
	}

	var results []*ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	sem := make(chan struct{}, concurrency)
	rateLimiter := time.Tick(time.Second / time.Duration(s.config.RateLimit))

	for ipUint := startUint; ipUint <= endUint; ipUint++ {
		ip := uint32ToIP(ipUint)
		for port := portStart; port <= portEnd; port++ {
			<-rateLimiter
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-sem }()
				result, err := s.Scan(ip, port)
				if err == nil {
					mu.Lock()
					results = append(results, result)
					mu.Unlock()
				}
			}(ip, port)
		}
	}

	wg.Wait()
	return results, nil
}

func (s *SYNScanner) tcpConnectScan(ip string, port int) (bool, error) {
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", addr, s.config.Timeout)
	if err != nil {
		return false, nil
	}
	conn.Close()
	return true, nil
}

func (s *SYNScanner) synScan(ip string, port int) (bool, error) {
	if !s.hasRawSock {
		return false, fmt.Errorf("raw socket not available: %s", s.rawSockErr)
	}
	return s.tcpConnectScan(ip, port)
}

func (s *SYNScanner) synFragmentScan(ip string, port int) (bool, error) {
	if !s.hasRawSock {
		return false, fmt.Errorf("raw socket not available: %s", s.rawSockErr)
	}
	return s.tcpConnectScan(ip, port)
}

func buildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort int, flags byte) []byte {
	tcpHeader := make([]byte, 20)

	binary.BigEndian.PutUint16(tcpHeader[0:2], uint16(srcPort))
	binary.BigEndian.PutUint16(tcpHeader[2:4], uint16(dstPort))
	binary.BigEndian.PutUint32(tcpHeader[4:8], uint32(rand.Intn(0xFFFFFFFF)))
	binary.BigEndian.PutUint32(tcpHeader[8:12], 0)
	tcpHeader[12] = 5 << 4
	tcpHeader[13] = flags
	binary.BigEndian.PutUint16(tcpHeader[14:16], 0xFFFF)
	binary.BigEndian.PutUint16(tcpHeader[16:18], 0)

	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], srcIP.To4())
	copy(pseudoHeader[4:8], dstIP.To4())
	pseudoHeader[8] = 0
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], 20)

	checksumData := append(pseudoHeader, tcpHeader...)
	checksum := tcpChecksum(checksumData)
	binary.BigEndian.PutUint16(tcpHeader[16:18], checksum)

	return tcpHeader
}

func tcpChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func buildIPHeader(srcIP, dstIP net.IP, protocol, totalLen int) []byte {
	ipHeader := make([]byte, 20)

	ipHeader[0] = 4<<4 | 5
	ipHeader[1] = 0
	binary.BigEndian.PutUint16(ipHeader[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(ipHeader[4:6], 0)
	binary.BigEndian.PutUint16(ipHeader[6:8], 0)
	ipHeader[8] = 64
	ipHeader[9] = byte(protocol)
	binary.BigEndian.PutUint16(ipHeader[10:12], 0)
	copy(ipHeader[12:16], srcIP.To4())
	copy(ipHeader[16:20], dstIP.To4())

	checksum := ipChecksum(ipHeader)
	binary.BigEndian.PutUint16(ipHeader[10:12], checksum)

	return ipHeader
}

func ipChecksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i < len(data)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	for sum > 0xffff {
		sum = (sum >> 16) + (sum & 0xffff)
	}
	return ^uint16(sum)
}

func fragmentPacket(packet []byte, mtu int) [][]byte {
	if len(packet) <= mtu {
		return [][]byte{packet}
	}

	var fragments [][]byte
	ipHeader := packet[:20]
	payload := packet[20:]

	fragSize := ((mtu - 20) / 8) * 8
	offset := 0

	for len(payload) > 0 {
		fragPayloadLen := fragSize
		if fragPayloadLen > len(payload) {
			fragPayloadLen = len(payload)
		}

		fragIPHeader := make([]byte, 20)
		copy(fragIPHeader, ipHeader)

		flagsOffset := uint16(offset / 8)
		if fragPayloadLen < len(payload) {
			flagsOffset |= 0x2000
		}
		binary.BigEndian.PutUint16(fragIPHeader[6:8], flagsOffset)
		binary.BigEndian.PutUint16(fragIPHeader[2:4], uint16(20+fragPayloadLen))
		binary.BigEndian.PutUint16(fragIPHeader[10:12], 0)

		checksum := ipChecksum(fragIPHeader)
		binary.BigEndian.PutUint16(fragIPHeader[10:12], checksum)

		fragment := append(fragIPHeader, payload[:fragPayloadLen]...)
		fragments = append(fragments, fragment)

		payload = payload[fragPayloadLen:]
		offset += fragPayloadLen
	}

	return fragments
}

func getSourceIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func ipToUint32(ipStr string) (uint32, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipStr)
	}
	ip = ip.To4()
	if ip == nil {
		return 0, fmt.Errorf("not an IPv4 address: %s", ipStr)
	}
	return binary.BigEndian.Uint32(ip), nil
}

func uint32ToIP(ipUint uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipUint)
	return ip.String()
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
