package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type hostResult struct {
	ip        string
	alive     bool
	openPorts []int
}

func main() {
	target := flag.String("t", "", "target: single IP, hostname, or CIDR (e.g. 192.168.1.0/24)")
	ports := flag.String("p", "1-1000", "ports: e.g. 22,80,443 or 1-1000")
	concurrency := flag.Int("c", 500, "max concurrent connections")
	timeout := flag.Duration("timeout", 500*time.Millisecond, "per-connection timeout")
	skipDiscovery := flag.Bool("Pn", false, "skip host discovery, scan all hosts as alive")
	synScan := flag.Bool("sS", false, "SYN scan (raw socket, requires root; default is TCP connect scan)")
	udpScan := flag.Bool("sU", false, "also scan UDP ports")
	banner := flag.Bool("sV", false, "grab service banners on open TCP ports")
	flag.Parse()

	if *synScan && !isRoot() {
		fmt.Fprintln(os.Stderr, "SYN scan (-sS) requires root or CAP_NET_RAW. Re-run with sudo, or drop -sS for a TCP connect scan.")
		os.Exit(1)
	}

	if *target == "" {
		fmt.Fprintln(os.Stderr, "usage: gomap -t <ip|cidr|hostname> [-p ports] [-c concurrency] [-Pn]")
		os.Exit(1)
	}

	ips, err := expandTarget(*target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "target error:", err)
		os.Exit(1)
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Fprintln(os.Stderr, "port error:", err)
		os.Exit(1)
	}

	start := time.Now()

	var alive []string
	if *skipDiscovery {
		alive = ips
	} else {
		fmt.Printf("Discovering hosts (%d candidates)...\n", len(ips))
		alive = discoverHosts(ips, *concurrency, *timeout)
		fmt.Printf("%d host(s) up\n\n", len(alive))
	}

	for _, ip := range alive {
		var open []int
		if *synScan {
			open = synScanPorts(ip, portList, *concurrency, *timeout)
		} else {
			open = scanPorts(ip, portList, *concurrency, *timeout)
		}

		banners := map[int]string{}
		if *banner {
			banners = grabBanners(ip, open, *concurrency, *timeout)
		}

		var udpOpen map[int]string
		if *udpScan {
			udpOpen = udpScanPorts(ip, portList, *concurrency, *timeout)
		}

		printResult(ip, open, banners, udpOpen)
	}

	fmt.Printf("\ndone in %s\n", time.Since(start).Round(time.Millisecond))
}

// expandTarget resolves a hostname, single IP, or CIDR into a list of IPs.
func expandTarget(target string) ([]string, error) {
	if strings.Contains(target, "/") {
		ip, ipnet, err := net.ParseCIDR(target)
		if err != nil {
			return nil, err
		}
		var ips []string
		for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur); incIP(cur) {
			ips = append(ips, cur.String())
		}
		// drop network and broadcast addresses for IPv4 /24 or larger, if more than 2 hosts
		if len(ips) > 2 {
			ips = ips[1 : len(ips)-1]
		}
		return ips, nil
	}

	if net.ParseIP(target) != nil {
		return []string{target}, nil
	}

	addrs, err := net.LookupHost(target)
	if err != nil {
		return nil, err
	}
	return addrs[:1], nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// parsePorts parses "22,80,443" or "1-1000" or a mix "22,80,1000-2000".
func parsePorts(spec string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			lo, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, err
			}
			hi, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, err
			}
			for p := lo; p <= hi; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, err
			}
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, fmt.Errorf("no ports specified")
	}
	return ports, nil
}

// discoverHosts pings (ICMP) candidate IPs concurrently; falls back to a TCP
// probe on common ports if raw ICMP sockets aren't permitted (no root).
func discoverHosts(ips []string, concurrency int, timeout time.Duration) []string {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	useICMP := err == nil
	if useICMP {
		conn.Close()
	}

	sem := make(chan struct{}, concurrency)
	results := make([]string, 0, len(ips))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, ip := range ips {
		ip := ip
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			var up bool
			if useICMP {
				up = icmpPing(ip, timeout)
			} else {
				up = tcpProbe(ip, timeout)
			}
			if up {
				mu.Lock()
				results = append(results, ip)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Strings(results)
	return results
}

func icmpPing(ip string, timeout time.Duration) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return tcpProbe(ip, timeout)
	}
	defer conn.Close()

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("gomap")},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return false
	}

	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteTo(b, dst); err != nil {
		return false
	}

	reply := make([]byte, 1500)
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}
	rm, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return false
	}
	return rm.Type == ipv4.ICMPTypeEchoReply
}

// tcpProbe checks a handful of commonly-open ports to guess liveness when
// ICMP isn't available (no raw socket privileges).
func tcpProbe(ip string, timeout time.Duration) bool {
	for _, p := range []int{80, 443, 22, 445, 3389} {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), timeout)
		if err == nil {
			conn.Close()
			return true
		}
	}
	return false
}

// scanPorts does a concurrent TCP connect scan against one host.
func scanPorts(ip string, ports []int, concurrency int, timeout time.Duration) []int {
	sem := make(chan struct{}, concurrency)
	var open []int
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, strconv.Itoa(p)), timeout)
			if err == nil {
				conn.Close()
				mu.Lock()
				open = append(open, p)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

func printResult(ip string, open []int, banners map[int]string, udpOpen map[int]string) {
	fmt.Printf("%s\n", ip)
	if len(open) == 0 && len(udpOpen) == 0 {
		fmt.Println("  no open ports found")
		return
	}
	for _, p := range open {
		line := fmt.Sprintf("  %d/tcp open  %s", p, serviceGuess(p))
		if b, ok := banners[p]; ok && b != "" {
			line += "  " + b
		}
		fmt.Println(line)
	}

	udpPorts := make([]int, 0, len(udpOpen))
	for p := range udpOpen {
		udpPorts = append(udpPorts, p)
	}
	sort.Ints(udpPorts)
	for _, p := range udpPorts {
		fmt.Printf("  %d/udp %-13s %s\n", p, udpOpen[p], serviceGuess(p))
	}
}

// grabBanners runs grabBanner concurrently across a host's open ports.
func grabBanners(ip string, ports []int, concurrency int, timeout time.Duration) map[int]string {
	sem := make(chan struct{}, concurrency)
	out := make(map[int]string)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		p := p
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			if b := grabBanner(ip, p, timeout); b != "" {
				mu.Lock()
				out[p] = b
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	return out
}

var commonServices = map[int]string{
	21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
	80: "http", 110: "pop3", 143: "imap", 443: "https",
	445: "smb", 3306: "mysql", 3389: "rdp", 5432: "postgresql",
	6379: "redis", 8080: "http-alt", 8443: "https-alt", 27017: "mongodb",
}

func serviceGuess(port int) string {
	if s, ok := commonServices[port]; ok {
		return s
	}
	return "unknown"
}
