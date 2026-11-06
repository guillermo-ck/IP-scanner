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
	"ip-scanner/internal/reporter"
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
	jsonOutput := flag.String("json", "", "Export results to JSON file (optional)")
	csvOutput := flag.String("csv", "", "Export results to CSV file (optional)")

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
	reporter.PrintConsoleTable(results)
	fmt.Printf("[*] Completed %d IP scans in %s\n", len(results), elapsed.Round(time.Millisecond))

	// 6. Export Reports (if requested)
	if *jsonOutput != "" {
		if err := reporter.ExportJSON(*jsonOutput, results); err != nil {
			log.Printf("[-] Failed to export JSON: %v\n", err)
		} else {
			fmt.Printf("[+] JSON report saved to: %s\n", *jsonOutput)
		}
	}

	if *csvOutput != "" {
		if err := reporter.ExportCSV(*csvOutput, results); err != nil {
			log.Printf("[-] Failed to export CSV: %v\n", err)
		} else {
			fmt.Printf("[+] CSV report saved to: %s\n", *csvOutput)
		}
	}
}
