package scanner

import (
	"io"
	"net/http"
	"net/url"
	"strings"
)

func TestXSS(form Form, baseURL string, client *http.Client) bool {
	payload := "<script>alert('XSS')</script>"
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

	return strings.Contains(body, payload)
}
