package threatintel

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// Scanner coordinates concurret threat intelligence lookups
type Scanner struct {
	abuseClient *AbuseIPDBClient
	vtClient    *VirusTotalClient
	rateLimiter <-chan time.Time
}

// NewScanner initializes the scanner with API clients and an internal rate limiter.
// rateInterval enforces a pause between external queries (e.g., 500ms or 15s depending on API tier)

func NewScanner(abuseKey, vtKey string, rateInterval time.Duration) *Scanner {
	var rateChan <-chan time.Time
	if rateInterval > 0 {
		rateChan = time.Tick(rateInterval)
	}
	//else {
	//	rateChan = make(chan time.Time) // Unbuffered channel, effectively no rate limiting
	//}

	return &Scanner{
		abuseClient: NewAbuseIPDBClient(abuseKey),
		vtClient:    NewVirusTotalClient(vtKey),
		rateLimiter: rateChan,
	}
}

// ScanIPs processes an IP slice concurrently across workerCount goroutines

func (s *Scanner) ScanIPs(ctx context.Context, ips []string, workerCount int) []ThreatResult {
	jobs := make(chan string, len(ips))
	results := make(chan ThreatResult, len(ips))

	var wg sync.WaitGroup

	//Spawn fixed worker pool (고루틴 작업자 풀 생성)
	for w := 1; w <= workerCount; w++ {
		wg.Add(1)
		go s.worker(ctx, &wg, jobs, results)
	}

	//Feed jobs (IP addresses) into the channel
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)

	//Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	//결과 수집
	var aggregated []ThreatResult
	for res := range results {
		aggregated = append(aggregated, res)
	}
	return aggregated
}

func (s *Scanner) worker(ctx context.Context, wg *sync.WaitGroup, jobs <-chan string, results chan<- ThreatResult) {
	defer wg.Done()
	for ip := range jobs {
		//Rate limiting (요청 속도 제한)
		if s.rateLimiter != nil {
			select {
			case <-ctx.Done():
				results <- ThreatResult{IP: ip, Err: ctx.Err()}
				return
			case <-s.rateLimiter:
				// Proceed with the request
			}
		}
		result := s.querySingleIP(ctx, ip)
		results <- result
	}
}

func (s *Scanner) querySingleIP(ctx context.Context, ip string) ThreatResult {
	res := ThreatResult{
		IP:        ip,
		QueriedAt: time.Now(),
	}
	//1 Query AbuseIPDB
	abuseResp, err := s.abuseClient.CheckIP(ctx, ip)
	if err != nil {
		res.Err = fmt.Errorf("AbuseIPDB error: %v", err)
		return res
	}
	res.AbuseScore = abuseResp.Data.AbuseConfidenceScore
	res.TotalReports = abuseResp.Data.TotalReports
	res.ISP = abuseResp.Data.ISP
	res.CountryCode = abuseResp.Data.CountryCode

	//2 Query VirusTotal
	vtResp, err := s.vtClient.CheckIP(ctx, ip)
	if err != nil {
		res.Err = fmt.Errorf("VirusTotal error: %v", err)
		return res
	}
	res.VTMalicious = vtResp.Data.Attributes.LastAnalysisStats.Malicious
	res.VTSuspicious = vtResp.Data.Attributes.LastAnalysisStats.Suspicious

	return res
}
