package report

import (
	"encoding/json"
	"os"
)

func SaveJSON(results []ScanResult, filename string) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(filename, data, 0644)
}
