package scanner

import (
	"fmt"
	"net/http"
)

func CheckSecurityHeaders(url string, client *http.Client) {
	fmt.Println("\n Verificando headers de segurança...")
	res, err := client.Get(url)
	if err != nil {
		fmt.Println("Erro:", err)
		return
	}
	defer res.Body.Close()

	headers := res.Header

	check := func(h string) {
		if headers.Get(h) == "" {
			fmt.Printf("Header ausente: %s\n", h)
		} else {
			fmt.Printf("Header presente: %s\n", h)
		}
	}

	check("Content-Security-Policy")
	check("X-Frame-Options")
	check("X-XSS-Protection")
	check("Strict-Transport-Security")
	check("Set-Cookie")
}
