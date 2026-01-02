package utils

import (
	"fmt"
	"net/url"
	"strings"
)

// ValidateURL valida e normaliza uma URL
func ValidateURL(rawURL string) (string, error) {
	if rawURL == "" {
		return "", fmt.Errorf("URL não pode ser vazia")
	}

	// Adiciona http:// se não tiver esquema
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}

	// Parse a URL
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("URL inválida: %w", err)
	}

	// Valida o esquema
	if parsedURL.Scheme != "http" && parsedURL.Scheme != "https" {
		return "", fmt.Errorf("esquema inválido: apenas http e https são suportados")
	}

	// Valida o host
	if parsedURL.Host == "" {
		return "", fmt.Errorf("host não pode ser vazio")
	}

	return parsedURL.String(), nil
}

// SanitizeInput remove caracteres perigosos de inputs
func SanitizeInput(input string) string {
	// Remove espaços no início e fim
	input = strings.TrimSpace(input)
	
	// Remove caracteres de controle
	var result strings.Builder
	for _, r := range input {
		if r >= 32 && r != 127 {
			result.WriteRune(r)
		}
	}
	
	return result.String()
}

// ValidateLoginFields valida campos de login
func ValidateLoginFields(loginURL, userField, passField, user, pass string) error {
	if _, err := ValidateURL(loginURL); err != nil {
		return fmt.Errorf("URL de login inválida: %w", err)
	}

	if userField == "" {
		return fmt.Errorf("campo de usuário não pode ser vazio")
	}

	if passField == "" {
		return fmt.Errorf("campo de senha não pode ser vazio")
	}

	if user == "" {
		return fmt.Errorf("usuário não pode ser vazio")
	}

	if pass == "" {
		return fmt.Errorf("senha não pode ser vazia")
	}

	return nil
}
