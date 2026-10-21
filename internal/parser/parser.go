package parser

import (
	"bufio"
	"net"
	"os"
	"regexp"
)

// Regex pattern to capture IPv4 strings
var ipv4Regex = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

//ExtracPublicIPs reads a log file, deduplicates addresses
// and filters private, loopback or invalid adddresses.

func ExtractPublicIPs(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	uniqueIPs := make(map[string]struct{})
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		matches := ipv4Regex.FindAllString(line, -1)

		for _, match := range matches {
			parsedIP := net.ParseIP(match)
			if parsedIP == nil {
				continue
			}
			//keep only valid IPv4 pubclic addresses
			if parsedIP.To4() != nil && isPublicIP(parsedIP) {
				uniqueIPs[parsedIP.String()] = struct{}{}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}
	// Convert map to slice
	result := make([]string, 0, len(uniqueIPs))
	for ip := range uniqueIPs {
		result = append(result, ip)
	}
	return result, nil
}

// isPublicIP checks if the given IP address is public
func isPublicIP(ip net.IP) bool {
	return !ip.IsLoopback() &&
		!ip.IsPrivate() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast()
}
