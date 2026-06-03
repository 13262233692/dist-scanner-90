package common

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
)

func IPToUint32(ipStr string) (uint32, error) {
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

func Uint32ToIP(ipUint uint32) string {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, ipUint)
	return ip.String()
}

func IPRangeCount(startIP, endIP string) (uint64, error) {
	start, err := IPToUint32(startIP)
	if err != nil {
		return 0, err
	}
	end, err := IPToUint32(endIP)
	if err != nil {
		return 0, err
	}
	if end < start {
		return 0, fmt.Errorf("end IP is less than start IP")
	}
	return uint64(end - start + 1), nil
}

func ParseIPRange(ipRange string) (string, string, error) {
	if strings.Contains(ipRange, "-") {
		parts := strings.SplitN(ipRange, "-", 2)
		return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]), nil
	}
	if strings.Contains(ipRange, "/") {
		_, ipNet, err := net.ParseCIDR(ipRange)
		if err != nil {
			return "", "", err
		}
		startIP := ipNet.IP.To4()
		if startIP == nil {
			return "", "", fmt.Errorf("only IPv4 CIDR is supported")
		}
		mask := binary.BigEndian.Uint32(ipNet.Mask)
		start := binary.BigEndian.Uint32(startIP)
		end := start | ^mask
		return Uint32ToIP(start), Uint32ToIP(end), nil
	}
	return ipRange, ipRange, nil
}

func ParsePortRange(portRange string) (int, int, error) {
	if strings.Contains(portRange, ",") {
		return 0, 0, fmt.Errorf("comma-separated ports not supported, use range format (e.g., 80-443)")
	}
	if strings.Contains(portRange, "-") {
		parts := strings.SplitN(portRange, "-", 2)
		var start, end int
		_, err := fmt.Sscanf(parts[0], "%d", &start)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range: %s", portRange)
		}
		_, err = fmt.Sscanf(parts[1], "%d", &end)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid port range: %s", portRange)
		}
		if start < 1 || end > 65535 || start > end {
			return 0, 0, fmt.Errorf("invalid port range: %s (must be 1-65535)", portRange)
		}
		return start, end, nil
	}
	var port int
	_, err := fmt.Sscanf(portRange, "%d", &port)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port: %s", portRange)
	}
	if port < 1 || port > 65535 {
		return 0, 0, fmt.Errorf("invalid port: %d (must be 1-65535)", port)
	}
	return port, port, nil
}

func GenerateTaskID() string {
	return fmt.Sprintf("task-%d", NextID())
}

func GenerateWorkerID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("worker-%s-%d", hostname, NextID())
}

var idCounter uint64

func NextID() uint64 {
	return atomicAdd(&idCounter, 1)
}

func atomicAdd(val *uint64, delta uint64) uint64 {
	return atomic.AddUint64(val, delta)
}
