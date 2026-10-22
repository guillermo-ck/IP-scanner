package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

const abuseIPDBEndpoint = "https://api.abuseipdb.com/api/v2/check"

type AbuseIPDBClient struct {
	apiKey     string
	httpClient *http.Client
}

func NewAbuseIPDBClient(apiKey string) *AbuseIPDBClient {
	return &AbuseIPDBClient{
		apiKey: apiKey,
		httpClient: &http.Client{
			Timeout: 10 * time.Second, // Timeout Control (타임아웃 제어)
		},
	}
}

// CheckIP queries the AbuseIPDB API for a single IP address
func (c *AbuseIPDBClient) CheckIP(ctx context.Context, ip string) (*AbuseIPDBResponse, error) {
	reqURL, err := url.Parse(abuseIPDBEndpoint)
	if err != nil {
		return nil, err
	}

	q := reqURL.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	q.Set("verbose", "true")
	reqURL.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// Required Headers (요청 헤더 설정)
	req.Header.Set("Key", c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests {
		return nil, fmt.Errorf("abuseipdb rate limit exceeded (429 Too Many Requests)")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("abuseipdb returned non-200 status: %d", resp.StatusCode)
	}

	var result AbuseIPDBResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode abuseipdb response: %w", err)
	}

	return &result, nil
}
