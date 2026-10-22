package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"ip-scanner/internal/parser"
	"ip-scanner/internal/threatintel"

	"github.com/joho/godotenv"
)

func main() {
	// 1. Load environment variables
	envPath := filepath.Join(".", ".env")
	if err := godotenv.Load(envPath); err != nil {
		log.Printf("[!] Warning: godotenv error on %s: %v\n", envPath, err)
	}

	abuseKey := os.Getenv("ABUSEIPDB_API_KEY")
	vtKey := os.Getenv("VIRUSTOTAL_API_KEY")

	if abuseKey == "" || vtKey == "" {
		log.Fatal("[-] Missing API keys. Ensure ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY are configured.")
	}

	// 2. CLI arguments (CLI 플래그 설정)
	logPath := flag.String("file", "", "Path to the log file to analyze")
	workers := flag.Int("workers", 2, "Number of concurrent worker goroutines")
	rateLimitSec := flag.Int("delay", 15, "Delay in seconds between requests to respect API rate limits")
	flag.Parse()

	if *logPath == "" {
		fmt.Println("Usage: go run cmd/scanner/main.go -file <path_to_log> [-workers <num>] [-delay <sec>]")
		os.Exit(1)
	}

	// 3. Extract public IPs
	extractedIPs, err := parser.ExtractPublicIPs(*logPath)
	if err != nil {
		log.Fatalf("[-] Failed to process log: %v", err)
	}

	if len(extractedIPs) == 0 {
		fmt.Println("[*] No public IP addresses found to scan.")
		return
	}

	fmt.Printf("[+] Extracted %d unique public IP(s).\n", len(extractedIPs))
	fmt.Printf("[*] Launching worker pool: %d workers | Rate limiter: %ds interval\n\n", *workers, *rateLimitSec)

	// 4. Initialize scanner and run concurrent execution (동시성 스캔 실행)
	scanner := threatintel.NewScanner(abuseKey, vtKey, time.Duration(*rateLimitSec)*time.Second)
	ctx := context.Background()

	startTime := time.Now()
	results := scanner.ScanIPs(ctx, extractedIPs, *workers)
	elapsed := time.Since(startTime)

	// 5. Output raw results
	fmt.Println("\n======================= SCAN RESULTS =======================")
	for _, res := range results {
		if res.Err != nil {
			fmt.Printf("[-] IP: %-15s | Error: %v\n", res.IP, res.Err)
			continue
		}

		fmt.Printf("[+] IP: %-15s | Country: %-2s | ISP: %-20s | AbuseScore: %3d%% | VT Malicious: %2d\n",
			res.IP,
			res.CountryCode,
			res.ISP,
			res.AbuseScore,
			res.VTMalicious,
		)
	}
	fmt.Println("============================================================")
	fmt.Printf("[*] Completed %d IP checks in %s\n", len(results), elapsed.Round(time.Millisecond))
}
