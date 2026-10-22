package threatintel

import "time"

// AbuseIPDBResponse maps the response from AbuseIPDB API v2
type AbuseIPDBResponse struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		IsPublic             bool   `json:"isPublic"`
		IPVersion            int    `json:"ipVersion"`
		IsWhitelisted        bool   `json:"isWhitelisted"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		Domain               string `json:"domain"`
		TotalReports         int    `json:"totalReports"`
		NumDistinctUsers     int    `json:"numDistinctUsers"`
		LastReportedAt       string `json:"lastReportedAt"`
	} `json:"data"`
}

// VirusTotalResponse maps the response from VirusTotal API v3
type VirusTotalResponse struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Reputation int    `json:"reputation"`
			AsOwner    string `json:"as_owner"`
			Country    string `json:"country"`
		} `json:"attributes"`
	} `json:"data"`
}

// ThreatResult aggregates intelligence data for an IP (통합 위협 분석 결과)
type ThreatResult struct {
	IP           string
	AbuseScore   int
	TotalReports int
	VTMalicious  int
	VTSuspicious int
	ISP          string
	CountryCode  string
	Err          error
	QueriedAt    time.Time
}
