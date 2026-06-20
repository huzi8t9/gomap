package main

import (
	"net"
	"strconv"
	"strings"
	"time"
)

// grabBanner connects to ip:port and tries to read a service banner. Some
// protocols (SSH, FTP, SMTP) volunteer a banner on connect; others (HTTP)
// stay silent until probed, so a minimal HEAD request is sent as a fallback.
func grabBanner(ip string, port int, timeout time.Duration) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(timeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		conn.SetDeadline(time.Now().Add(timeout))
		n, err = conn.Read(buf)
		if err != nil || n == 0 {
			return ""
		}
	}
	banner := strings.SplitN(string(buf[:n]), "\n", 2)[0]
	return strings.TrimSpace(banner)
}
