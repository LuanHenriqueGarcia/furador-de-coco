package utils

import (
	"net/http"
	"net/http/cookiejar"
)

func NewHttpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
	}
	return client
}
