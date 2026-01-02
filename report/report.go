package report

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// ScanResult representa o resultado de um scan de vulnerabilidades
type ScanResult struct {
	URL         string
	FormAction  string
	FormMethod  string
	Timestamp   time.Time
	XSS         bool
	SQLi        bool
	XSSDetails  []VulnDetail
	SQLiDetails []VulnDetail
}

// VulnDetail armazena detalhes de uma vulnerabilidade
type VulnDetail struct {
	Vulnerable  bool
	Payload     string
	Description string
	Field       string
	Response    string
	Type        string
	Indicator   string
}

// ScanReport representa um relatório completo de scan
type ScanReport struct {
	StartTime       time.Time
	EndTime         time.Time
	TargetURL       string
	FormsScanned    int
	VulnsFound      int
	Results         []ScanResult
	SecurityHeaders []HeaderResult
	CookieResults   []CookieResult
	CSRFResults     []CSRFResult
}

// HeaderResult representa resultado de checagem de header
type HeaderResult struct {
	Name     string
	Present  bool
	Value    string
	Severity string
	Message  string
}

// CookieResult representa resultado de checagem de cookie
type CookieResult struct {
	Name     string
	Secure   bool
	HTTPOnly bool
	SameSite string
	Issues   []string
}

// CSRFResult representa resultado de checagem CSRF
type CSRFResult struct {
	FormAction string
	Protected  bool
	TokenFound bool
	Message    string
}

// SaveTxt salva o relatório em formato texto
func SaveTxt(results []ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintf(file, "=== RELATÓRIO DE VULNERABILIDADES ===\n")
	fmt.Fprintf(file, "Gerado em: %s\n\n", time.Now().Format("02/01/2006 15:04:05"))

	for i, r := range results {
		fmt.Fprintf(file, "--- Formulário %d ---\n", i+1)
		fmt.Fprintf(file, "URL: %s\n", r.URL)
		fmt.Fprintf(file, "Action: %s\n", r.FormAction)
		fmt.Fprintf(file, "Method: %s\n", r.FormMethod)
		fmt.Fprintf(file, "Timestamp: %s\n", r.Timestamp.Format("15:04:05"))
		fmt.Fprintf(file, "\nVulnerabilidades:\n")
		fmt.Fprintf(file, "  XSS: %v\n", r.XSS)
		fmt.Fprintf(file, "  SQLi: %v\n", r.SQLi)
		
		if len(r.XSSDetails) > 0 {
			fmt.Fprintf(file, "\nDetalhes XSS:\n")
			for _, detail := range r.XSSDetails {
				if detail.Vulnerable {
					fmt.Fprintf(file, "  - Campo: %s\n", detail.Field)
					fmt.Fprintf(file, "    Payload: %s\n", detail.Payload)
					fmt.Fprintf(file, "    Descrição: %s\n", detail.Description)
				}
			}
		}
		
		if len(r.SQLiDetails) > 0 {
			fmt.Fprintf(file, "\nDetalhes SQLi:\n")
			for _, detail := range r.SQLiDetails {
				if detail.Vulnerable {
					fmt.Fprintf(file, "  - Campo: %s\n", detail.Field)
					fmt.Fprintf(file, "    Payload: %s\n", detail.Payload)
					fmt.Fprintf(file, "    Tipo: %s\n", detail.Type)
					fmt.Fprintf(file, "    Indicador: %s\n", detail.Indicator)
				}
			}
		}
		
		fmt.Fprintln(file, "\n" + strings.Repeat("-", 50))
	}

	return nil
}
