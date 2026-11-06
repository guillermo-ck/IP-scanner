package threatintel

import "time"

// ThreatVeredict - categorizes the severity level 위협 심각도 등급)
type ThreatVerdict string

const (
	VerdictMalicious  ThreatVerdict = "MALICIOUS"
	VerdictSuspicious ThreatVerdict = "SUSPICIOUS"
	VerdictBenign     ThreatVerdict = "BENIGN"
)

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
	IP           string        `json:"ip"`
	Verdict      ThreatVerdict `json:"verdict"`
	AbuseScore   int           `json:"abuse_score"`
	TotalReports int           `json:"total_reports"`
	VTMalicious  int           `json:"vt_malicious"`
	VTSuspicious int           `json:"vt_suspicious"`
	ISP          string        `json:"isp"`
	CountryCode  string        `json:"country_code"`
	Err          error         `json:"-"`
	QueriedAt    time.Time     `json:"queried_at"`
}

func (r *ThreatResult) CalculateVerdict() {
	if r.AbuseScore >= 50 || r.VTMalicious > 3 {
		r.Verdict = VerdictMalicious
	} else if r.AbuseScore >= 15 || r.VTMalicious > 1 || r.VTSuspicious > 2 {
		r.Verdict = VerdictSuspicious
	} else {
		r.Verdict = VerdictBenign
	}
}
