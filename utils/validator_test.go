package utils

import (
	"testing"
)

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:    "URL válida com http",
			input:   "http://example.com",
			want:    "http://example.com",
			wantErr: false,
		},
		{
			name:    "URL válida com https",
			input:   "https://example.com",
			want:    "https://example.com",
			wantErr: false,
		},
		{
			name:    "URL sem esquema (adiciona http)",
			input:   "example.com",
			want:    "http://example.com",
			wantErr: false,
		},
		{
			name:    "URL com path",
			input:   "http://example.com/path/to/page",
			want:    "http://example.com/path/to/page",
			wantErr: false,
		},
		{
			name:    "URL com query string",
			input:   "http://example.com?param=value",
			want:    "http://example.com?param=value",
			wantErr: false,
		},
		{
			name:    "URL vazia",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "URL sem host",
			input:   "http://",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ValidateURL(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateURL() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ValidateURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSanitizeInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "String normal",
			input: "hello world",
			want:  "hello world",
		},
		{
			name:  "String com espaços nas pontas",
			input: "  hello world  ",
			want:  "hello world",
		},
		{
			name:  "String com tabs e newlines",
			input: "hello\tworld\n",
			want:  "helloworld",
		},
		{
			name:  "String vazia",
			input: "",
			want:  "",
		},
		{
			name:  "String com caracteres especiais válidos",
			input: "hello@example.com",
			want:  "hello@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeInput(tt.input)
			if got != tt.want {
				t.Errorf("SanitizeInput() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateLoginFields(t *testing.T) {
	tests := []struct {
		name      string
		loginURL  string
		userField string
		passField string
		user      string
		pass      string
		wantErr   bool
	}{
		{
			name:      "Todos os campos válidos",
			loginURL:  "http://example.com/login",
			userField: "username",
			passField: "password",
			user:      "admin",
			pass:      "admin123",
			wantErr:   false,
		},
		{
			name:      "URL de login inválida",
			loginURL:  "",
			userField: "username",
			passField: "password",
			user:      "admin",
			pass:      "admin123",
			wantErr:   true,
		},
		{
			name:      "Campo de usuário vazio",
			loginURL:  "http://example.com/login",
			userField: "",
			passField: "password",
			user:      "admin",
			pass:      "admin123",
			wantErr:   true,
		},
		{
			name:      "Senha vazia",
			loginURL:  "http://example.com/login",
			userField: "username",
			passField: "password",
			user:      "admin",
			pass:      "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateLoginFields(tt.loginURL, tt.userField, tt.passField, tt.user, tt.pass)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateLoginFields() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
