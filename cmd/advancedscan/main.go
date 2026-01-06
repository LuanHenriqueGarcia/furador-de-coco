package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"furador-de-coco/auth"
	"furador-de-coco/logger"
	"furador-de-coco/scanner"
	"furador-de-coco/utils"
)

func main() {
	fmt.Println(`
+===========================================+
|   FURADOR DE COCO - ADVANCED SCAN        |
|   Teste de Vulnerabilidades Avançadas    |
+===========================================+
`)

	// Parse flags
	url := flag.String("url", "", "URL alvo (obrigatório)")
	useLogin := flag.Bool("login", false, "Fazer login antes")
	loginURL := flag.String("login-url", "", "URL de login")
	username := flag.String("username", "", "Usuário")
	password := flag.String("password", "", "Senha")
	userField := flag.String("user-field", "username", "Nome do campo de usuário")
	passField := flag.String("pass-field", "password", "Nome do campo de senha")
	verbose := flag.Bool("verbose", true, "Modo verbose")
	useJS := flag.Bool("js", true, "Usar JavaScript rendering")

	flag.Parse()

	if *url == "" {
		fmt.Println("ERRO: URL é obrigatória")
		fmt.Println("\nUso: go run cmd/advancedscan/main.go -url <URL> [opções]")
		flag.PrintDefaults()
		os.Exit(1)
	}

	if *verbose {
		logger.SetLevel(logger.DEBUG)
	}

	logger.Info("Iniciando scan avançado em: %s", *url)

	// Valida URL
	validatedURL, err := utils.ValidateURL(*url)
	if err != nil {
		logger.Fatal("URL inválida: %v", err)
	}

	// Setup HTTP client
	var httpClient = utils.NewHttpClientWithTimeout(30 * time.Second)

	if *useLogin && *loginURL != "" {
		logger.Info("Fazendo login...")
		session, err := auth.Login(*loginURL, *userField, *passField, *username, *password)
		if err != nil {
			logger.Fatal("Erro ao fazer login: %v", err)
		}
		httpClient = session.Client
		logger.Success("Login realizado com sucesso")
	}

	// Busca formulários
	logger.Info("Buscando formulários...")
	var forms []scanner.Form

	if *useJS {
		logger.Info("Usando modo headless (JavaScript)")
		rendered, err := scanner.GetRenderedHTML(validatedURL)
		if err != nil {
			logger.Fatal("Erro ao renderizar HTML: %v", err)
		}
		forms = scanner.ParseFormsFromHTML(rendered)
	} else {
		forms, err = scanner.GetForms(validatedURL, httpClient)
		if err != nil {
			logger.Fatal("Erro ao buscar formulários: %v", err)
		}
	}

	logger.Success("Encontrados %d formulário(s)", len(forms))

	// Testes básicos (XSS, SQLi, CSRF)
	logger.Info("Executando testes básicos...")
	for i, form := range forms {
		logger.Debug("Testando formulário %d", i+1)
		
		xss := scanner.TestXSSDetailed(form, validatedURL, httpClient)
		for _, result := range xss {
			if result.Vulnerable {
				logger.Warn("XSS detectado no campo '%s'", result.Field)
			}
		}

		sqli := scanner.TestSQLiDetailed(form, validatedURL, httpClient)
		for _, result := range sqli {
			if result.Vulnerable {
				logger.Warn("SQLi detectado no campo '%s'", result.Field)
			}
		}
	}

	// Testes avançados
	logger.Info("\nExecutando testes avançados de segurança...")
	
	var allResults []scanner.AdvancedVulnResult

	logger.Info("Testando Directory Traversal...")
	dirResults := scanner.TestDirectoryTraversal(validatedURL, httpClient)
	allResults = append(allResults, dirResults...)

	logger.Info("Testando Local File Inclusion...")
	lfiResults := scanner.TestLFI(validatedURL, httpClient)
	allResults = append(allResults, lfiResults...)

	for _, form := range forms {
		logger.Info("Testando Command Injection...")
		cmdResults := scanner.TestCommandInjection(form, validatedURL, httpClient)
		allResults = append(allResults, cmdResults...)

		logger.Info("Testando XXE...")
		xxeResults := scanner.TestXXE(form, validatedURL, httpClient)
		allResults = append(allResults, xxeResults...)

		logger.Info("Testando Open Redirect...")
		redirectResults := scanner.TestOpenRedirect(form, validatedURL, httpClient)
		allResults = append(allResults, redirectResults...)

		logger.Info("Testando SSRF...")
		ssrfResults := scanner.TestSSRF(form, validatedURL, httpClient)
		allResults = append(allResults, ssrfResults...)
	}

	// Headers de segurança
	logger.Info("Verificando headers de segurança...")
	headerResults := scanner.CheckSecurityHeaders(validatedURL, httpClient)
	scanner.PrintSecurityHeaders(headerResults)

	// Cookies
	logger.Info("Verificando segurança de cookies...")
	scanner.CheckCookieSecurity(validatedURL, httpClient)

	// CSRF
	if len(forms) > 0 {
		logger.Info("Verificando proteção CSRF...")
		scanner.CheckCSRFProtection(forms)
	}

	// Imprime resultados avançados
	scanner.PrintAdvancedResults(allResults)

	// Resumo final
	fmt.Println("\n" + strings.Repeat("=", 80))
	fmt.Printf("\nSCAN COMPLETO!")
	fmt.Printf("\nFormas testadas: %d", len(forms))
	fmt.Printf("\nVulnerabilidades críticas encontradas: %d", countCritical(allResults))
	fmt.Printf("\nTotal de vulnerabilidades: %d\n", len(allResults))
	
	if len(allResults) > 0 {
		fmt.Println("\n[!!!] SISTEMA VULNERÁVEL - CORREÇÕES NECESSÁRIAS!")
	} else {
		fmt.Println("\n[OK] Nenhuma vulnerabilidade crítica detectada")
	}

	logger.Success("Scan avançado concluído!")
}

func countCritical(results []scanner.AdvancedVulnResult) int {
	count := 0
	for _, r := range results {
		if r.Severity == "CRITICAL" {
			count++
		}
	}
	return count
}
