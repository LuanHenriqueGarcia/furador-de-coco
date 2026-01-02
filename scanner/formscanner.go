package scanner

import (
	"net/http"
	"strings"

	"golang.org/x/net/html"
)

type Form struct {
	Action string
	Method string
	Inputs []string
}

func GetForms(url string, client *http.Client) ([]Form, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return parseHTML(resp.Body)
}

func parseHTML(input interface{}) ([]Form, error) {
	var htmlNode *html.Node
	var err error

	switch v := input.(type) {
	case *http.Response:
		htmlNode, err = html.Parse(v.Body)
	case string:
		htmlNode, err = html.Parse(strings.NewReader(v))
	}

	if err != nil {
		return nil, err
	}

	var forms []Form
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form := Form{Method: "GET"}
			for _, attr := range n.Attr {
				if attr.Key == "action" {
					form.Action = attr.Val
				}
				if attr.Key == "method" {
					form.Method = strings.ToUpper(attr.Val)
				}
			}
			for c := n.FirstChild; c != nil; c = c.NextSibling {
				if c.Type == html.ElementNode && (c.Data == "input" || c.Data == "textarea" || c.Data == "select") {
					for _, attr := range c.Attr {
						if attr.Key == "name" {
							form.Inputs = append(form.Inputs, attr.Val)
						}
					}
				}
			}
			forms = append(forms, form)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(htmlNode)
	return forms, nil
}

func ParseFormsFromHTML(html string) []Form {
	forms, _ := parseHTML(html)
	return forms
}
