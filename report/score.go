package report

import "fmt"

func PrintRiskScore(results []ScanResult) {
	score := 0
	for _, r := range results {
		if r.XSS {
			score += 2
		}
		if r.SQLi {
			score += 3
		}
	}

	var level string
	switch {
	case score >= 5:
		level = " ALTO"
	case score >= 2:
		level = " MÉDIO"
	default:
		level = " BAIXO"
	}

	fmt.Printf("\nScore de risco: %d pontos — Nível: %s\n", score, level)
}
