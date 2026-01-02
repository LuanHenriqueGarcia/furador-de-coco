package scanner

import (
	"fmt"
	"strings"
)

var csrfFieldNames = []string{
	"csrf_token",
	"_csrf",
	"authenticity_token",
	"csrfmiddlewaretoken",
}

func CheckCSRFProtection(forms []Form) {
	fmt.Println("\nVerificando proteção contra CSRF:")

	for i, form := range forms {
		hasToken := false
		for _, input := range form.Inputs {
			for _, tokenName := range csrfFieldNames {
				if strings.ToLower(input) == strings.ToLower(tokenName) {
					hasToken = true
					break
				}
			}
		}

		if hasToken {
			fmt.Printf("Formulário %d tem proteção CSRF.\n", i+1)
		} else {
			fmt.Printf("Formulário %d NÃO tem proteção CSRF.\n", i+1)
		}
	}
}
