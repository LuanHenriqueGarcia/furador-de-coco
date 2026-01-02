package ui

import (
	"github.com/manifoldco/promptui"
)

func SelectURL(urls []string) (string, error) {
	prompt := promptui.Select{
		Label: "Escolha uma URL para escanear",
		Items: urls,
	}
	_, result, err := prompt.Run()
	return result, err
}
