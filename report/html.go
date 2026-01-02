package report

import (
	"fmt"
	"html"
	"os"
	"time"
)

// SaveHTML salva o relatório em formato HTML com estilo
func SaveHTML(results []ScanResult, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	// Header HTML com CSS
	file.WriteString(`<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="utf-8">
    <title>Relatório de Vulnerabilidades - Furador de Coco</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            background: #f5f5f5;
            padding: 20px;
        }
        .container { 
            max-width: 1200px; 
            margin: 0 auto; 
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 8px 8px 0 0;
        }
        .header h1 { margin-bottom: 10px; }
        .header .timestamp { opacity: 0.9; font-size: 14px; }
        .content { padding: 30px; }
        .summary { 
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .summary-card h3 { color: #333; margin-bottom: 10px; font-size: 14px; }
        .summary-card .value { font-size: 32px; font-weight: bold; color: #667eea; }
        .form-result {
            background: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        .form-header { 
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 2px solid #f0f0f0;
        }
        .form-title { font-size: 18px; font-weight: 600; color: #333; }
        .form-meta { font-size: 13px; color: #666; }
        .vulnerability {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 4px;
            font-size: 12px;
            font-weight: 600;
            margin-right: 10px;
            margin-top: 5px;
        }
        .vuln-high { background: #fee; color: #c00; border: 1px solid #fcc; }
        .vuln-safe { background: #efe; color: #060; border: 1px solid #cfc; }
        .details { 
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 4px;
        }
        .details h4 { 
            color: #c00;
            margin-bottom: 10px;
            font-size: 14px;
        }
        .detail-item {
            margin: 10px 0;
            padding: 10px;
            background: white;
            border-left: 3px solid #c00;
            font-size: 13px;
        }
        .detail-item strong { color: #333; }
        .payload { 
            font-family: 'Courier New', monospace;
            background: #f0f0f0;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
        }
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            font-size: 12px;
            border-top: 1px solid #e0e0e0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🥥 Relatório de Vulnerabilidades - Furador de Coco</h1>
            <div class="timestamp">Gerado em: ` + time.Now().Format("02/01/2006 às 15:04:05") + `</div>
        </div>
        <div class="content">`)

	// Summary
	vulnCount := 0
	for _, r := range results {
		if r.XSS || r.SQLi {
			vulnCount++
		}
	}

	file.WriteString(`<div class="summary">
        <div class="summary-card">
            <h3>Formulários Escaneados</h3>
            <div class="value">` + fmt.Sprintf("%d", len(results)) + `</div>
        </div>
        <div class="summary-card">
            <h3>Vulnerabilidades Encontradas</h3>
            <div class="value">` + fmt.Sprintf("%d", vulnCount) + `</div>
        </div>
    </div>`)

	// Resultados
	for i, r := range results {
		file.WriteString(fmt.Sprintf(`
        <div class="form-result">
            <div class="form-header">
                <div>
                    <div class="form-title">Formulário #%d</div>
                    <div class="form-meta">URL: %s</div>
                    <div class="form-meta">Action: %s | Method: %s</div>
                </div>
            </div>
            <div>`, i+1, html.EscapeString(r.URL), html.EscapeString(r.FormAction), r.FormMethod))

		// Vulnerabilidades
		if r.XSS {
			file.WriteString(`<span class="vulnerability vuln-high">🚨 XSS VULNERÁVEL</span>`)
		} else {
			file.WriteString(`<span class="vulnerability vuln-safe">✓ XSS Seguro</span>`)
		}

		if r.SQLi {
			file.WriteString(`<span class="vulnerability vuln-high">🚨 SQLi VULNERÁVEL</span>`)
		} else {
			file.WriteString(`<span class="vulnerability vuln-safe">✓ SQLi Seguro</span>`)
		}

		// Detalhes XSS
		if len(r.XSSDetails) > 0 {
			hasVuln := false
			for _, detail := range r.XSSDetails {
				if detail.Vulnerable {
					hasVuln = true
					break
				}
			}
			if hasVuln {
				file.WriteString(`<div class="details"><h4>Detalhes de XSS:</h4>`)
				for _, detail := range r.XSSDetails {
					if detail.Vulnerable {
						file.WriteString(fmt.Sprintf(`
                        <div class="detail-item">
                            <strong>Campo:</strong> %s<br>
                            <strong>Payload:</strong> <span class="payload">%s</span><br>
                            <strong>Descrição:</strong> %s
                        </div>`,
							html.EscapeString(detail.Field),
							html.EscapeString(detail.Payload),
							html.EscapeString(detail.Description)))
					}
				}
				file.WriteString(`</div>`)
			}
		}

		// Detalhes SQLi
		if len(r.SQLiDetails) > 0 {
			hasVuln := false
			for _, detail := range r.SQLiDetails {
				if detail.Vulnerable {
					hasVuln = true
					break
				}
			}
			if hasVuln {
				file.WriteString(`<div class="details"><h4>Detalhes de SQL Injection:</h4>`)
				for _, detail := range r.SQLiDetails {
					if detail.Vulnerable {
						file.WriteString(fmt.Sprintf(`
                        <div class="detail-item">
                            <strong>Campo:</strong> %s<br>
                            <strong>Payload:</strong> <span class="payload">%s</span><br>
                            <strong>Tipo:</strong> %s<br>
                            <strong>Indicador:</strong> %s
                        </div>`,
							html.EscapeString(detail.Field),
							html.EscapeString(detail.Payload),
							html.EscapeString(detail.Type),
							html.EscapeString(detail.Indicator)))
					}
				}
				file.WriteString(`</div>`)
			}
		}

		file.WriteString(`</div></div>`)
	}

	// Footer
	file.WriteString(`
        </div>
        <div class="footer">
            Furador de Coco - Security Scanner | Relatório gerado automaticamente
        </div>
    </div>
</body>
</html>`)

	return nil
}
