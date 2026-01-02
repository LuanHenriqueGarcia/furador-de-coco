package main

import (
	"fmt"
	"net/http"

	"furador-de-poco/auth"
	"furador-de-poco/report"
	"furador-de-poco/scanner"
	"furador-de-poco/ui"
)

func main() {
	urls := []string{
		"http://testphp.vulnweb.com/",
		"https://example.com",
	}

	url, err := ui.SelectURL(urls)
	if err != nil {
		fmt.Println("Erro na seleção de URL:", err)
		return
	}

	var useJS string
	fmt.Print("Usar modo headless (renderizar JavaScript)? (s/n): ")
	fmt.Scanln(&useJS)

	var useLogin string
	fmt.Print("Você quer fazer login antes de escanear? (s/n): ")
	fmt.Scanln(&useLogin)

	var httpClient *http.Client

	if useLogin == "s" {
		var loginURL, userField, passField, user, pass string
		fmt.Print("URL de login: ")
		fmt.Scanln(&loginURL)
		fmt.Print("Campo de usuário (name=): ")
		fmt.Scanln(&userField)
		fmt.Print("Campo de senha (name=): ")
		fmt.Scanln(&passField)
		fmt.Print("Usuário: ")
		fmt.Scanln(&user)
		fmt.Print("Senha: ")
		fmt.Scanln(&pass)

		session, err := auth.Login(loginURL, userField, passField, user, pass)
		if err != nil {
			fmt.Println("Erro ao logar:", err)
			return
		}
		httpClient = session.Client
		fmt.Println("Login bem-sucedido.")
	} else {
		httpClient = http.DefaultClient
	}

	var forms []scanner.Form
	if useJS == "s" {
		rendered, err := scanner.GetRenderedHTML(url)
		if err != nil {
			fmt.Println("Erro ao renderizar com JavaScript:", err)
			return
		}
		forms = scanner.ParseFormsFromHTML(rendered)
	} else {
		forms, err = scanner.GetForms(url, httpClient)
		if err != nil {
			fmt.Println("Erro ao escanear:", err)
			return
		}
	}

	fmt.Printf("[+] %d formulários encontrados\n", len(forms))

	var results []report.ScanResult

	for i, form := range forms {
		fmt.Printf("-> Formulário %d: action='%s' method='%s'\n", i+1, form.Action, form.Method)

		vulnXSS := scanner.TestXSS(form, url, httpClient)
		if vulnXSS {
			fmt.Println("Vulnerabilidade XSS detectada!")
		} else {
			fmt.Println("Nenhuma XSS detectada.")
		}

		vulnSQLi := scanner.TestSQLi(form, url, httpClient)
		if vulnSQLi {
			fmt.Println("Vulnerabilidade SQL Injection detectada!")
		} else {
			fmt.Println("Nenhuma SQLi detectada.")
		}

		results = append(results, report.ScanResult{
			URL:  url,
			XSS:  vulnXSS,
			SQLi: vulnSQLi,
		})
	}

	scanner.CheckCSRFProtection(forms)
	scanner.CheckSecurityHeaders(url, httpClient)

	report.SaveTxt(results, "relatorio.txt")
	report.SaveHTML(results, "relatorio.html")
	fmt.Println(" Relatórios salvos em relatorio.txt e relatorio.html")
}
