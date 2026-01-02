package auth

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

type AuthSession struct {
	Client *http.Client
}

func Login(loginURL, usernameField, passwordField, username, password string) (*AuthSession, error) {
	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
	}

	data := url.Values{}
	data.Set(usernameField, username)
	data.Set(passwordField, password)

	_, err := client.PostForm(loginURL, data)
	if err != nil {
		return nil, err
	}

	return &AuthSession{Client: client}, nil
}
