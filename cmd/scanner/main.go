package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"ip-scanner/internal/parser"
	"ip-scanner/internal/threatintel"

	"github.com/joho/godotenv"
)

func main() {
	// 1. Load environment variables (.env 파일 로드)
	err := godotenv.Load(".env")
	if err != nil {
		log.Printf("[!] Failed to load .env: %v\n", err)
	}

	abuseKey := os.Getenv("ABUSEIPDB_API_KEY")
	vtKey := os.Getenv("VIRUSTOTAL_API_KEY")

	if abuseKey == "" || vtKey == "" {
		log.Fatal("[-] Missing API keys. Ensure ABUSEIPDB_API_KEY and VIRUSTOTAL_API_KEY are set.")
	}

	// 2. Parse CLI flag //명렬졸 인수 파싱
	logPath := flag.String("file", "", "Path to the log file")
	flag.Parse()

	if *logPath == "" {
		fmt.Println("Usage: go run cmd/scanner/main.go -file <path_to_log>")
		os.Exit(1)
	}

	// 3. Extract public IPs
	extractedIPs, err := parser.ExtractPublicIPs(*logPath)
	if err != nil {
		log.Fatalf("[-] Failed to process log: %v", err)
	}

	fmt.Printf("[+] Extracted %d unique public IP(s). Starting lookup...\n\n", len(extractedIPs))

	abuseClient := threatintel.NewAbuseIPDBClient(abuseKey)
	vtClient := threatintel.NewVirusTotalClient(vtKey)
	ctx := context.Background()

	// 4. Sequential lookup test (Phase 3 will upgrade this to a concurrent worker pool)
	for _, ip := range extractedIPs {
		fmt.Printf("🔍 Scanning IP: %s\n", ip)

		// AbuseIPDB Lookup
		abuseData, err := abuseClient.CheckIP(ctx, ip)
		if err != nil {
			fmt.Printf("  [!] AbuseIPDB error: %v\n", err)
		} else {
			fmt.Printf("  [AbuseIPDB] Score: %d%% | Reports: %d | ISP: %s | Country: %s\n",
				abuseData.Data.AbuseConfidenceScore,
				abuseData.Data.TotalReports,
				abuseData.Data.ISP,
				abuseData.Data.CountryCode,
			)
		}

		// VirusTotal Lookup
		vtData, err := vtClient.CheckIP(ctx, ip)
		if err != nil {
			fmt.Printf("  [!] VirusTotal error: %v\n", err)
		} else {
			stats := vtData.Data.Attributes.LastAnalysisStats
			fmt.Printf("  [VirusTotal] Malicious: %d | Suspicious: %d | Harmless: %d\n",
				stats.Malicious,
				stats.Suspicious,
				stats.Harmless,
			)
		}
		fmt.Println("-----------------------------------------------------------------")
	}
}
