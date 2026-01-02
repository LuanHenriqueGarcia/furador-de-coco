package scanner

import (
	"fmt"
	"net/http"
)

func CheckCookieSecurity(url string, client *http.Client) {
	fmt.Println("\nVerificando cookies:")

	resp, err := client.Get(url)
	if err != nil {
		fmt.Println("Erro ao acessar página:", err)
		return
	}
	defer resp.Body.Close()

	for _, cookie := range resp.Cookies() {
		fmt.Printf("- %s: ", cookie.Name)
		if !cookie.Secure {
			fmt.Print("falta Secure, ")
		}
		if !cookie.HttpOnly {
			fmt.Print("falta HttpOnly, ")
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			fmt.Print("falta SameSite")
		}
		fmt.Println()
	}
}
