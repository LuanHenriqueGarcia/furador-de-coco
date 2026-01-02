package config

import (
	"flag"
	"fmt"
	"time"
)

// Config armazena todas as configurações do scanner
type Config struct {
	// URL alvo
	URL string

	// Modo de scan
	UseJS       bool
	UseLogin    bool
	Verbose     bool
	Workers     int
	Timeout     time.Duration
	RateLimit   time.Duration

	// Login
	LoginURL   string
	UserField  string
	PassField  string
	Username   string
	Password   string

	// Outputs
	OutputDir   string
	OutputHTML  bool
	OutputJSON  bool
	OutputTXT   bool

	// Scan options
	TestXSS     bool
	TestSQLi    bool
	TestCSRF    bool
	TestHeaders bool
	TestCookies bool
}

// NewConfig cria uma nova configuração com valores padrão
func NewConfig() *Config {
	return &Config{
		Workers:     5,
		Timeout:     30 * time.Second,
		RateLimit:   100 * time.Millisecond,
		OutputDir:   ".",
		OutputHTML:  true,
		OutputJSON:  true,
		OutputTXT:   true,
		TestXSS:     true,
		TestSQLi:    true,
		TestCSRF:    true,
		TestHeaders: true,
		TestCookies: true,
	}
}

// ParseFlags configura e parseia as flags da linha de comando
func (c *Config) ParseFlags() error {
	flag.StringVar(&c.URL, "url", "", "URL alvo para escanear (obrigatório)")
	flag.BoolVar(&c.UseJS, "js", false, "Usar modo headless para renderizar JavaScript")
	flag.BoolVar(&c.UseLogin, "login", false, "Fazer login antes de escanear")
	flag.BoolVar(&c.Verbose, "verbose", false, "Modo verbose (logs detalhados)")
	flag.IntVar(&c.Workers, "workers", 5, "Número de workers paralelos")
	
	var timeoutSec int
	flag.IntVar(&timeoutSec, "timeout", 30, "Timeout em segundos para requisições HTTP")
	
	var rateLimitMs int
	flag.IntVar(&rateLimitMs, "rate-limit", 100, "Delay em ms entre requisições")

	flag.StringVar(&c.LoginURL, "login-url", "", "URL da página de login")
	flag.StringVar(&c.UserField, "user-field", "", "Nome do campo de usuário")
	flag.StringVar(&c.PassField, "pass-field", "", "Nome do campo de senha")
	flag.StringVar(&c.Username, "username", "", "Usuário para login")
	flag.StringVar(&c.Password, "password", "", "Senha para login")

	flag.StringVar(&c.OutputDir, "output", ".", "Diretório para salvar relatórios")
	flag.BoolVar(&c.OutputHTML, "html", true, "Gerar relatório HTML")
	flag.BoolVar(&c.OutputJSON, "json", true, "Gerar relatório JSON")
	flag.BoolVar(&c.OutputTXT, "txt", true, "Gerar relatório TXT")

	flag.BoolVar(&c.TestXSS, "test-xss", true, "Testar vulnerabilidades XSS")
	flag.BoolVar(&c.TestSQLi, "test-sqli", true, "Testar vulnerabilidades SQLi")
	flag.BoolVar(&c.TestCSRF, "test-csrf", true, "Testar proteção CSRF")
	flag.BoolVar(&c.TestHeaders, "test-headers", true, "Testar headers de segurança")
	flag.BoolVar(&c.TestCookies, "test-cookies", true, "Testar segurança de cookies")

	flag.Parse()

	c.Timeout = time.Duration(timeoutSec) * time.Second
	c.RateLimit = time.Duration(rateLimitMs) * time.Millisecond

	return c.Validate()
}

// Validate valida a configuração
func (c *Config) Validate() error {
	if c.URL == "" {
		return fmt.Errorf("URL é obrigatória (use -url)")
	}

	if c.UseLogin {
		if c.LoginURL == "" || c.UserField == "" || c.PassField == "" || 
		   c.Username == "" || c.Password == "" {
			return fmt.Errorf("quando --login é usado, todos os campos de login são obrigatórios")
		}
	}

	if c.Workers < 1 {
		return fmt.Errorf("número de workers deve ser >= 1")
	}

	if c.Workers > 20 {
		return fmt.Errorf("número de workers deve ser <= 20")
	}

	return nil
}
