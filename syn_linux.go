//go:build linux

package main

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sync"
	"time"
)

func isRoot() bool {
	return os.Geteuid() == 0
}

// synScanPorts performs a raw-socket TCP SYN scan against a single host.
// Requires root / CAP_NET_RAW. Ports that never answer within the timeout
// are treated as filtered and left out of the open list.
func synScanPorts(targetIP string, ports []int, concurrency int, timeout time.Duration) []int {
	localIP, err := localIPFor(targetIP)
	if err != nil {
		fmt.Fprintln(os.Stderr, "syn scan: could not determine local IP:", err)
		return nil
	}
	dstIP := net.ParseIP(targetIP)
	if dstIP == nil {
		fmt.Fprintln(os.Stderr, "syn scan: bad target IP:", targetIP)
		return nil
	}

	rconn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: localIP})
	if err != nil {
		fmt.Fprintln(os.Stderr, "syn scan: raw socket (need root/CAP_NET_RAW):", err)
		return nil
	}
	defer rconn.Close()

	wconn, err := net.DialIP("ip4:tcp", &net.IPAddr{IP: localIP}, &net.IPAddr{IP: dstIP})
	if err != nil {
		fmt.Fprintln(os.Stderr, "syn scan: raw socket dial:", err)
		return nil
	}
	defer wconn.Close()

	srcPort := uint16(40000 + rand.Intn(20000))

	results := make(map[uint16]chan string)
	var mu sync.Mutex

	go func() {
		buf := make([]byte, 4096)
		for {
			n, _, err := rconn.ReadFrom(buf)
			if err != nil {
				return
			}
			if n < 20 {
				continue
			}
			gotSrcPort := binary.BigEndian.Uint16(buf[0:2])
			gotDstPort := binary.BigEndian.Uint16(buf[2:4])
			if gotDstPort != srcPort {
				continue
			}
			flags := buf[13]
			mu.Lock()
			ch, ok := results[gotSrcPort]
			mu.Unlock()
			if !ok {
				continue
			}
			switch {
			case flags&0x12 == 0x12: // SYN+ACK
				ch <- "open"
			case flags&0x04 != 0: // RST
				ch <- "closed"
			}
		}
	}()

	sem := make(chan struct{}, concurrency)
	var open []int
	var openMu sync.Mutex
	var wg sync.WaitGroup

	for _, p := range ports {
		p := p
		dstPort := uint16(p)

		ch := make(chan string, 1)
		mu.Lock()
		results[dstPort] = ch
		mu.Unlock()

		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				mu.Lock()
				delete(results, dstPort)
				mu.Unlock()
			}()

			pkt := buildSYN(localIP, dstIP, srcPort, dstPort)
			if _, err := wconn.Write(pkt); err != nil {
				return
			}

			select {
			case state := <-ch:
				if state == "open" {
					openMu.Lock()
					open = append(open, p)
					openMu.Unlock()
				}
			case <-time.After(timeout):
				// filtered: dropped or blocked, no response
			}
		}()
	}
	wg.Wait()
	return open
}

func localIPFor(dst string) (net.IP, error) {
	conn, err := net.Dial("udp4", net.JoinHostPort(dst, "80"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}

// buildSYN crafts a bare TCP SYN segment (no IP header — the kernel fills
// that in for a raw "ip4:tcp" socket) with a correct checksum.
func buildSYN(srcIP, dstIP net.IP, srcPort, dstPort uint16) []byte {
	seq := rand.Uint32()
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], srcPort)
	binary.BigEndian.PutUint16(hdr[2:4], dstPort)
	binary.BigEndian.PutUint32(hdr[4:8], seq)
	binary.BigEndian.PutUint32(hdr[8:12], 0) // ack
	hdr[12] = 0x50                           // data offset: 5 words, no options
	hdr[13] = 0x02                           // flags: SYN
	binary.BigEndian.PutUint16(hdr[14:16], 64240) // window
	binary.BigEndian.PutUint16(hdr[16:18], 0)     // checksum placeholder
	binary.BigEndian.PutUint16(hdr[18:20], 0)     // urgent pointer

	checksum := tcpChecksum(srcIP.To4(), dstIP.To4(), hdr)
	binary.BigEndian.PutUint16(hdr[16:18], checksum)
	return hdr
}

func tcpChecksum(srcIP, dstIP net.IP, tcpSeg []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpSeg))
	copy(pseudo[0:4], srcIP)
	copy(pseudo[4:8], dstIP)
	pseudo[8] = 0
	pseudo[9] = 6 // TCP protocol number
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpSeg)))
	copy(pseudo[12:], tcpSeg)

	var sum uint32
	for i := 0; i < len(pseudo)-1; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	if len(pseudo)%2 == 1 {
		sum += uint32(pseudo[len(pseudo)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}
