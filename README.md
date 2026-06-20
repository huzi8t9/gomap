# gomap

A fast, concurrent network port scanner written in Go.

## Features

- **TCP connect scan** (default) — works without root
- **SYN scan** (`-sS`) — stealthier half-open scan; requires root / `CAP_NET_RAW`, Linux only
- **UDP scan** (`-sU`) — probes UDP ports with protocol-aware payloads for DNS, NTP, and SNMP
- **Banner grabbing** (`-sV`) — reads service banners from open TCP ports
- **Host discovery** — ICMP ping when run as root, TCP probe fallback otherwise; skip with `-Pn`
- Targets: single IP, hostname, or CIDR range
- Flexible port spec: individual ports, ranges, or a mix

## Requirements

- Go 1.21 or later

## Build

```bash
git clone https://github.com/markhughes/gomap.git
cd gomap
go build -o gomap .
```

Or install directly to `$GOPATH/bin`:

```bash
go install github.com/markhughes/gomap@latest
```

## Usage

```
gomap -t <ip|cidr|hostname> [options]

Options:
  -t <target>       Target: single IP, hostname, or CIDR (e.g. 192.168.1.0/24)
  -p <ports>        Ports to scan (default: 1-1000)
                    Examples: 22,80,443  |  1-1000  |  22,80,1000-2000
  -c <n>            Max concurrent connections (default: 500)
  --timeout <d>     Per-connection timeout (default: 500ms)
  -Pn               Skip host discovery; treat all hosts as alive
  -sS               SYN scan — requires root/CAP_NET_RAW (Linux only)
  -sU               Also scan UDP ports
  -sV               Grab service banners on open TCP ports
```

## Examples

**Scan the top 1000 ports on a single host:**
```bash
./gomap -t 192.168.1.1
```

**Scan specific ports on a hostname:**
```bash
./gomap -t example.com -p 22,80,443,8080
```

**Scan a port range:**
```bash
./gomap -t 10.0.0.1 -p 1-65535
```

**Scan an entire subnet (host discovery + port scan):**
```bash
./gomap -t 192.168.1.0/24
```

**Skip host discovery and scan all addresses in a subnet:**
```bash
./gomap -t 192.168.1.0/24 -Pn
```

**Grab service banners on open ports:**
```bash
./gomap -t 192.168.1.1 -sV
```

**SYN scan (requires root):**
```bash
sudo ./gomap -t 192.168.1.1 -sS
```

**Include UDP ports alongside TCP:**
```bash
./gomap -t 192.168.1.1 -sU
```

**Tune concurrency and timeout for a slow network:**
```bash
./gomap -t 10.0.0.1 -c 100 --timeout 2s
```

**Full scan: SYN + UDP + banners across a subnet:**
```bash
sudo ./gomap -t 192.168.1.0/24 -p 1-1024 -sS -sU -sV
```

## Example output

```
Discovering hosts (254 candidates)...
3 host(s) up

192.168.1.1
  22/tcp  open  ssh    SSH-2.0-OpenSSH_8.9
  80/tcp  open  http   HTTP/1.1 301 Moved Permanently
  443/tcp open  https

192.168.1.10
  3306/tcp open  mysql
  22/tcp   open  ssh

192.168.1.20
  no open ports found

done in 1.243s
```

## Notes

- **Permissions:** Host discovery via ICMP and SYN scans (`-sS`) require root or `CAP_NET_RAW`. Without these privileges, host discovery falls back to TCP probing common ports (22, 80, 443, 445, 3389).
- **Responsible use:** Only scan hosts and networks you own or have explicit authorisation to test.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).
