package reporter

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"text/tabwriter"

	"ip-scanner/internal/threatintel"
)

// PrintConsoleTable prints a clean tabular summary to the terminal
func PrintConsoleTable(results []threatintel.ThreatResult) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', tabwriter.Debug)
	fmt.Fprintln(w, "\nIP ADDRESS\tVERDICT\tABUSE SCORE\tVT MALICIOUS\tCOUNTRY\tISP")
	fmt.Fprintln(w, "----------\t-------\t-----------\t------------\t-------\t---")

	for _, r := range results {
		if r.Err != nil {
			fmt.Fprintf(w, "%s\tERROR\t-\t-\t-\t%v\n", r.IP, r.Err)
			continue
		}
		fmt.Fprintf(w, "%s\t%s\t%d%%\t%d\t%s\t%s\n",
			r.IP,
			r.Verdict,
			r.AbuseScore,
			r.VTMalicious,
			r.CountryCode,
			r.ISP,
		)
	}
	w.Flush()
	fmt.Println()
}

// ExportJSON writes scan results to a formatted JSON file (JSON 보고서 저장)
func ExportJSON(filename string, results []threatintel.ThreatResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(results)
}

// ExportCSV exports scan results to a structured CSV file (CSV 보고서 저장)
func ExportCSV(filename string, results []threatintel.ThreatResult) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write CSV Header
	header := []string{"IP", "Verdict", "AbuseScore", "TotalReports", "VTMalicious", "VTSuspicious", "Country", "ISP", "QueriedAt"}
	if err := writer.Write(header); err != nil {
		return err
	}

	for _, r := range results {
		if r.Err != nil {
			continue
		}
		row := []string{
			r.IP,
			string(r.Verdict),
			strconv.Itoa(r.AbuseScore),
			strconv.Itoa(r.TotalReports),
			strconv.Itoa(r.VTMalicious),
			strconv.Itoa(r.VTSuspicious),
			r.CountryCode,
			r.ISP,
			r.QueriedAt.Format("2006-01-02 15:04:05"),
		}
		if err := writer.Write(row); err != nil {
			return err
		}
	}

	return nil
}
