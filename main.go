package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"furador-de-coco/auth"
	"furador-de-coco/config"
	"furador-de-coco/logger"
	"furador-de-coco/report"
	"furador-de-coco/scanner"
	"furador-de-coco/ui"
	"furador-de-coco/utils"
)

func main() {
	printBanner()

	// Carrega configuração
	cfg := config.NewConfig()
	if err := cfg.ParseFlags(); err != nil {
		logger.Error("Erro ao carregar configuração: %v", err)
		fmt.Println("\nUso: furador-de-coco -url <URL> [opções]")
		fmt.Println("Use -h para ver todas as opções disponíveis")
		os.Exit(1)
	}

	// Configura logger
	if cfg.Verbose {
		logger.SetLevel(logger.DEBUG)
	}

	// Valida URL
	validatedURL, err := utils.ValidateURL(cfg.URL)
	if err != nil {
		logger.Fatal("URL inválida: %v", err)
	}
	cfg.URL = validatedURL

	logger.Info("Iniciando scan em: %s", cfg.URL)
	logger.Info("Workers: %d | Timeout: %v | Rate Limit: %v", 
		cfg.Workers, cfg.Timeout, cfg.RateLimit)

	// Configura HTTP client
	httpClient := setupHTTPClient(cfg)

	// Busca formulários
	logger.Info("Buscando formulários...")
	forms, err := getForms(cfg, httpClient)
	if err != nil {
		logger.Fatal("Erro ao buscar formulários: %v", err)
	}

	if len(forms) == 0 {
		logger.Warn("Nenhum formulário encontrado em %s", cfg.URL)
		os.Exit(0)
	}

	logger.Success("Encontrados %d formulário(s)", len(forms))

	// Executa scan com worker pool
	results := runScan(cfg, forms, httpClient)

	// Checagens adicionais
	if cfg.TestHeaders {
		logger.Info("Verificando headers de segurança...")
		headerResults := scanner.CheckSecurityHeaders(cfg.URL, httpClient)
		scanner.PrintSecurityHeaders(headerResults)
	}

	if cfg.TestCookies {
		logger.Info("Verificando segurança de cookies...")
		scanner.CheckCookieSecurity(cfg.URL, httpClient)
	}

	if cfg.TestCSRF {
		logger.Info("Verificando proteção CSRF...")
		scanner.CheckCSRFProtection(forms)
	}

	// Salva relatórios
	saveReports(cfg, results)

	// Calcula e exibe score de risco
	report.PrintRiskScore(results)

	logger.Success("Scan concluído com sucesso!")
}

func printBanner() {
	banner := `
+===========================================+
|     FURADOR DE COCO                      |
|     Security Vulnerability Scanner        |
|     v2.0 - Enhanced Edition              |
+===========================================+
`
	fmt.Println(banner)
}

func setupHTTPClient(cfg *config.Config) *http.Client {
	var httpClient *http.Client

	if cfg.UseLogin {
		logger.Info("Fazendo login...")
		
		if err := utils.ValidateLoginFields(
			cfg.LoginURL, cfg.UserField, cfg.PassField, 
			cfg.Username, cfg.Password); err != nil {
			logger.Fatal("Campos de login inválidos: %v", err)
		}

		session, err := auth.Login(
			cfg.LoginURL, cfg.UserField, cfg.PassField,
			cfg.Username, cfg.Password)
		if err != nil {
			logger.Fatal("Erro ao fazer login: %v", err)
		}
		
		httpClient = session.Client
		httpClient.Timeout = cfg.Timeout
		logger.Success("Login realizado com sucesso")
	} else {
		httpClient = utils.NewHttpClientWithTimeout(cfg.Timeout)
	}

	return httpClient
}

func getForms(cfg *config.Config, httpClient *http.Client) ([]scanner.Form, error) {
	if cfg.UseJS {
		logger.Info("Usando modo headless (JavaScript)")
		rendered, err := scanner.GetRenderedHTML(cfg.URL)
		if err != nil {
			return nil, err
		}
		return scanner.ParseFormsFromHTML(rendered), nil
	}
	
	return scanner.GetForms(cfg.URL, httpClient)
}

func runScan(cfg *config.Config, forms []scanner.Form, httpClient *http.Client) []report.ScanResult {
	logger.Info("Iniciando scan de vulnerabilidades...")
	
	progressBar := ui.NewProgressBar(len(forms))
	
	var results []report.ScanResult

	// Sem worker pool quando apenas 1 worker ou poucos formulários
	if cfg.Workers == 1 || len(forms) <= 2 {
		for i, form := range forms {
			result := scanForm(form, cfg.URL, httpClient, i+1)
			results = append(results, result)
			progressBar.Increment()
		}
		progressBar.Finish()
	} else {
		// Usa worker pool para paralelização
		pool := scanner.NewWorkerPool(cfg.Workers, cfg.RateLimit)
		pool.Start(httpClient)

		// Submete jobs
		for i, form := range forms {
			pool.Submit(scanner.ScanJob{
				Form:      form,
				BaseURL:   cfg.URL,
				FormIndex: i,
			})
		}

		// Fecha o canal de jobs
		go func() {
			pool.Close()
		}()

		// Coleta resultados
		for i := 0; i < len(forms); i++ {
			jobResult := <-pool.Results()
			
			result := report.ScanResult{
				URL:        cfg.URL,
				FormAction: jobResult.Form.Action,
				FormMethod: jobResult.Form.Method,
				Timestamp:  time.Now(),
				XSS:        jobResult.XSSVuln,
				SQLi:       jobResult.SQLiVuln,
			}

			// Converte XSSResults
			for _, xss := range jobResult.XSSResults {
				result.XSSDetails = append(result.XSSDetails, report.VulnDetail{
					Vulnerable:  xss.Vulnerable,
					Payload:     xss.Payload,
					Description: xss.Description,
					Field:       xss.Field,
					Response:    xss.Response,
				})
			}

			// Converte SQLiResults
			for _, sqli := range jobResult.SQLiResults {
				result.SQLiDetails = append(result.SQLiDetails, report.VulnDetail{
					Vulnerable:  sqli.Vulnerable,
					Payload:     sqli.Payload,
					Description: sqli.Description,
					Field:       sqli.Field,
					Response:    sqli.Response,
					Type:        sqli.Type,
					Indicator:   sqli.Indicator,
				})
			}

			results = append(results, result)
			progressBar.Increment()
		}

		progressBar.Finish()
	}

	return results
}

func scanForm(form scanner.Form, baseURL string, httpClient *http.Client, index int) report.ScanResult {
	logger.Debug("Escaneando formulário %d: action='%s' method='%s'", 
		index, form.Action, form.Method)

	result := report.ScanResult{
		URL:        baseURL,
		FormAction: form.Action,
		FormMethod: form.Method,
		Timestamp:  time.Now(),
	}

	// Testa XSS
	xssResults := scanner.TestXSSDetailed(form, baseURL, httpClient)
	for _, xss := range xssResults {
		if xss.Vulnerable {
			result.XSS = true
			logger.Warn("XSS detectado no formulário %d, campo '%s'", index, xss.Field)
		}
		result.XSSDetails = append(result.XSSDetails, report.VulnDetail{
			Vulnerable:  xss.Vulnerable,
			Payload:     xss.Payload,
			Description: xss.Description,
			Field:       xss.Field,
			Response:    xss.Response,
		})
	}

	// Testa SQLi
	sqliResults := scanner.TestSQLiDetailed(form, baseURL, httpClient)
	for _, sqli := range sqliResults {
		if sqli.Vulnerable {
			result.SQLi = true
			logger.Warn("SQLi detectado no formulário %d, campo '%s'", index, sqli.Field)
		}
		result.SQLiDetails = append(result.SQLiDetails, report.VulnDetail{
			Vulnerable:  sqli.Vulnerable,
			Payload:     sqli.Payload,
			Description: sqli.Description,
			Field:       sqli.Field,
			Response:    sqli.Response,
			Type:        sqli.Type,
			Indicator:   sqli.Indicator,
		})
	}

	return result
}

func saveReports(cfg *config.Config, results []report.ScanResult) {
	logger.Info("Gerando relatórios...")

	if cfg.OutputTXT {
		filename := filepath.Join(cfg.OutputDir, "relatorio.txt")
		if err := report.SaveTxt(results, filename); err != nil {
			logger.Error("Erro ao salvar TXT: %v", err)
		} else {
			logger.Success("Relatório TXT salvo: %s", filename)
		}
	}

	if cfg.OutputHTML {
		filename := filepath.Join(cfg.OutputDir, "relatorio.html")
		if err := report.SaveHTML(results, filename); err != nil {
			logger.Error("Erro ao salvar HTML: %v", err)
		} else {
			logger.Success("Relatório HTML salvo: %s", filename)
		}
	}

	if cfg.OutputJSON {
		filename := filepath.Join(cfg.OutputDir, "relatorio.json")
		if err := report.SaveJSON(results, filename); err != nil {
			logger.Error("Erro ao salvar JSON: %v", err)
		} else {
			logger.Success("Relatório JSON salvo: %s", filename)
		}
	}
}
