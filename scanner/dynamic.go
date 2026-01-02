package scanner

import (
	"context"
	"time"

	"github.com/chromedp/chromedp"
)

func GetRenderedHTML(url string) (string, error) {
	ctx, cancel := chromedp.NewContext(context.Background())
	defer cancel()

	var html string

	timeoutCtx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()

	err := chromedp.Run(timeoutCtx,
		chromedp.Navigate(url),
		chromedp.Sleep(1*time.Second), 
		chromedp.OuterHTML("html", &html),
	)

	if err != nil {
		return "", err
	}

	return html, nil
}
