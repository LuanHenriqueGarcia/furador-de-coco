package report

import (
	"fmt"
	"os"
)

type ScanResult struct {
	URL      string
	XSS      bool
	SQLi     bool
}

func SaveTxt(results []ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	for _, r := range results {
		fmt.Fprintf(file, "URL: %s\n", r.URL)
		fmt.Fprintf(file, "XSS: %v\n", r.XSS)
		fmt.Fprintf(file, "SQLi: %v\n", r.SQLi)
		fmt.Fprintln(file, "--------------------------")
	}

	return nil
}
