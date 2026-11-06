# IP-scanner
# Automated Threat Intelligence & IP Reputation Scanner (CLI)

[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)](#)
[![CTI Integration](https://img.shields.io/badge/CTI-AbuseIPDB%20%7C%20VirusTotal-orange)](#)

A high-throughput command-line interface (CLI) tool engineered in **Go** for security operations (SOC) teams and incident responders. It parses raw server access logs, extracts and deduplicates routable public IP addresses, queries external Threat Intelligence feeds concurrently via worker pools, and compiles structured incident triage reports (Console Table, CSV, and JSON).

---

## 📌 Architecture & Data Pipeline (아키텍처 및 파이프라인)

```text
[ Server Access Log (.log) ]
             │
             ▼
   [ Stream-based Parser ] ──────► Regex extraction via `bufio.Scanner`
             │                   Filters out RFC 1918 Private, Loopback & Invalid IPs
             ▼
    [ Public IP Hash Set ] ──────► O(1) in-memory deduplication (`map[string]struct{}`)
             │
             ▼
   [ Worker Pool Engine ]  ──────► Managed Goroutines & Buffered Channels
             │                   Sync with `sync.WaitGroup` & Pacing via `time.Tick`
      ┌──────┴──────┐
      ▼             ▼
 [ AbuseIPDB ] [ VirusTotal ] ───► HTTP Clients with Context Timeouts (`context.WithTimeout`)
      └──────┬──────┘
             ▼
   [ Risk Scoring Engine ] ──────► Normalizes & evaluates verdict: MALICIOUS | SUSPICIOUS | BENIGN
             │
             ▼
    [ Triage Reporters ]   ──────► CLI Formatted Table (`tabwriter`) / CSV / JSON Export