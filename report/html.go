package report

import (
	"fmt"
	"os"
)

func SaveHTML(results []ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	file.WriteString("<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Relatório de Vulnerabilidades</title></head><body>")
	file.WriteString("<h1>Relatório de Vulnerabilidades</h1>")

	for _, r := range results {
		file.WriteString("<div style='margin-bottom:20px;'>")
		file.WriteString(fmt.Sprintf("<strong>URL:</strong> %s<br>", r.URL))
		file.WriteString(fmt.Sprintf("<strong>XSS:</strong> %v<br>", r.XSS))
		file.WriteString(fmt.Sprintf("<strong>SQLi:</strong> %v<br>", r.SQLi))
		file.WriteString("</div><hr>")
	}

	file.WriteString("</body></html>")
	return nil
}
