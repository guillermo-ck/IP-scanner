package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

const vtEndpoint = "https://www.virustotal.com/api/v3/ip_addresses/"

type VirusTotalClient struct {
	apiKey     string
	httpClient *http.Client
}

func NewVirusTotalClient(apiKey string) *VirusTotalClient {
	return &VirusTotalClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// CheckIP queries VirusTotal API v3 for a single IP address
func (c *VirusTotalClient) CheckIP(ctx context.Context, ip string) (*VirusTotalResponse, error) {
	targetURL := vtEndpoint + ip

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, err
	}

	// Required VT Header (x-apikey)
	req.Header.Set("x-apikey", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("virustotal rate limit exceeded (429 Too Many Requests)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("virustotal returned non-200 status: %d", resp.StatusCode)
	}

	var result VirusTotalResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode virustotal response: %w", err)
	}

	return &result, nil
}
