package scanner

import (
	"fmt"
	"net/http"
	"strings"
)

// SecurityHeader representa um header de segurança e sua análise
type SecurityHeader struct {
	Name     string
	Present  bool
	Value    string
	Severity string // "critical", "high", "medium", "low"
	Message  string
}

// CheckSecurityHeaders verifica headers de segurança de forma detalhada
func CheckSecurityHeaders(url string, client *http.Client) []SecurityHeader {
	res, err := client.Get(url)
	if err != nil {
		return []SecurityHeader{{Name: "Error", Message: err.Error(), Severity: "critical"}}
	}
	defer res.Body.Close()

	headers := res.Header
	var results []SecurityHeader

	// Content-Security-Policy
	csp := headers.Get("Content-Security-Policy")
	if csp == "" {
		results = append(results, SecurityHeader{
			Name:     "Content-Security-Policy",
			Present:  false,
			Severity: "high",
			Message:  "CSP ausente - aplicação vulnerável a XSS",
		})
	} else {
		results = append(results, SecurityHeader{
			Name:     "Content-Security-Policy",
			Present:  true,
			Value:    csp,
			Severity: "low",
			Message:  "CSP configurado",
		})
	}

	// X-Frame-Options
	xfo := headers.Get("X-Frame-Options")
	if xfo == "" {
		results = append(results, SecurityHeader{
			Name:     "X-Frame-Options",
			Present:  false,
			Severity: "medium",
			Message:  "X-Frame-Options ausente - vulnerável a clickjacking",
		})
	} else {
		results = append(results, SecurityHeader{
			Name:     "X-Frame-Options",
			Present:  true,
			Value:    xfo,
			Severity: "low",
			Message:  fmt.Sprintf("Configurado como: %s", xfo),
		})
	}

	// X-Content-Type-Options
	xcto := headers.Get("X-Content-Type-Options")
	if xcto == "" {
		results = append(results, SecurityHeader{
			Name:     "X-Content-Type-Options",
			Present:  false,
			Severity: "medium",
			Message:  "X-Content-Type-Options ausente - vulnerável a MIME sniffing",
		})
	} else {
		results = append(results, SecurityHeader{
			Name:     "X-Content-Type-Options",
			Present:  true,
			Value:    xcto,
			Severity: "low",
			Message:  "Configurado corretamente",
		})
	}

	// Strict-Transport-Security (HSTS)
	hsts := headers.Get("Strict-Transport-Security")
	if hsts == "" && strings.HasPrefix(url, "https") {
		results = append(results, SecurityHeader{
			Name:     "Strict-Transport-Security",
			Present:  false,
			Severity: "high",
			Message:  "HSTS ausente em site HTTPS - vulnerável a downgrade attacks",
		})
	} else if hsts != "" {
		results = append(results, SecurityHeader{
			Name:     "Strict-Transport-Security",
			Present:  true,
			Value:    hsts,
			Severity: "low",
			Message:  "HSTS configurado",
		})
	}

	// X-XSS-Protection (deprecated mas ainda útil para browsers antigos)
	xxp := headers.Get("X-XSS-Protection")
	if xxp == "" {
		results = append(results, SecurityHeader{
			Name:     "X-XSS-Protection",
			Present:  false,
			Severity: "low",
			Message:  "X-XSS-Protection ausente (deprecated, mas útil para browsers antigos)",
		})
	} else {
		results = append(results, SecurityHeader{
			Name:     "X-XSS-Protection",
			Present:  true,
			Value:    xxp,
			Severity: "low",
			Message:  fmt.Sprintf("Configurado como: %s", xxp),
		})
	}

	// Referrer-Policy
	rp := headers.Get("Referrer-Policy")
	if rp == "" {
		results = append(results, SecurityHeader{
			Name:     "Referrer-Policy",
			Present:  false,
			Severity: "low",
			Message:  "Referrer-Policy ausente - possível vazamento de informações via referrer",
		})
	} else {
		results = append(results, SecurityHeader{
			Name:     "Referrer-Policy",
			Present:  true,
			Value:    rp,
			Severity: "low",
			Message:  fmt.Sprintf("Configurado como: %s", rp),
		})
	}

	// Permissions-Policy (antigo Feature-Policy)
	pp := headers.Get("Permissions-Policy")
	if pp == "" {
		results = append(results, SecurityHeader{
			Name:     "Permissions-Policy",
			Present:  false,
			Severity: "low",
			Message:  "Permissions-Policy ausente - considere restringir features do navegador",
		})
	} else {
		results = append(results, SecurityHeader{
			Name:     "Permissions-Policy",
			Present:  true,
			Value:    pp,
			Severity: "low",
			Message:  "Permissions-Policy configurado",
		})
	}

	// Server header (info disclosure)
	server := headers.Get("Server")
	if server != "" {
		results = append(results, SecurityHeader{
			Name:     "Server",
			Present:  true,
			Value:    server,
			Severity: "low",
			Message:  fmt.Sprintf("Header Server expõe informações: %s", server),
		})
	}

	// X-Powered-By (info disclosure)
	xpb := headers.Get("X-Powered-By")
	if xpb != "" {
		results = append(results, SecurityHeader{
			Name:     "X-Powered-By",
			Present:  true,
			Value:    xpb,
			Severity: "low",
			Message:  fmt.Sprintf("Header X-Powered-By expõe tecnologia: %s", xpb),
		})
	}

	return results
}

// PrintSecurityHeaders imprime os headers de segurança de forma formatada
func PrintSecurityHeaders(headers []SecurityHeader) {
	fmt.Println("\n🔒 Verificação de Headers de Segurança:")
	fmt.Println(strings.Repeat("-", 70))

	for _, h := range headers {
		icon := "✓"
		if !h.Present && h.Severity != "low" {
			icon = "✗"
		} else if !h.Present {
			icon = "⚠"
		}

		fmt.Printf("%s [%s] %s\n", icon, strings.ToUpper(h.Severity), h.Name)
		fmt.Printf("  %s\n", h.Message)
		if h.Value != "" {
			fmt.Printf("  Valor: %s\n", h.Value)
		}
		fmt.Println()
	}
}
