package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"ip-scanner/internal/parser"
)

func main() {
	//Parse CLI flags (명렬졸 인수 파싱)
	logPath := flag.String("file", "", "Path to the log file")
	flag.Parse()

	if *logPath == "" {
		fmt.Println("Usage: go run cmd/scanner/main.go -file <path_to_log_file>")
		os.Exit(1)
	}

	fmt.Printf("[*] Parsing log file: %s\n", *logPath)

	extractedIPs, err := parser.ExtractPublicIPs(*logPath)
	if err != nil {
		log.Fatalf("[-] Failed to process log file: %v", err)

	}
	fmt.Printf("[+] Found %d unique public IPs:\n", len(extractedIPs))
	for _, ip := range extractedIPs {
		fmt.Printf(" 	-> %s\n", ip)
	}

}
