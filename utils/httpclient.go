package utils

import (
	"net/http"
	"net/http/cookiejar"
	"time"
)

// NewHttpClient cria um cliente HTTP com gerenciamento de cookies
func NewHttpClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	return client
}

// NewHttpClientWithTimeout cria um cliente HTTP com timeout configurável
func NewHttpClientWithTimeout(timeout time.Duration) *http.Client {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar:     jar,
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	return client
}
