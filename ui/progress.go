package ui

import (
	"fmt"
	"strings"
	"time"
)

// ProgressBar representa uma barra de progresso
type ProgressBar struct {
	total   int
	current int
	width   int
	start   time.Time
}

// NewProgressBar cria uma nova barra de progresso
func NewProgressBar(total int) *ProgressBar {
	return &ProgressBar{
		total: total,
		width: 50,
		start: time.Now(),
	}
}

// Update atualiza a barra de progresso
func (pb *ProgressBar) Update(current int) {
	pb.current = current
	pb.render()
}

// Increment incrementa a barra de progresso
func (pb *ProgressBar) Increment() {
	pb.current++
	pb.render()
}

// Finish finaliza a barra de progresso
func (pb *ProgressBar) Finish() {
	pb.current = pb.total
	pb.render()
	fmt.Println()
}

// render renderiza a barra de progresso
func (pb *ProgressBar) render() {
	percent := float64(pb.current) / float64(pb.total)
	if percent > 1 {
		percent = 1
	}

	filled := int(percent * float64(pb.width))
	empty := pb.width - filled

	bar := strings.Repeat("█", filled) + strings.Repeat("░", empty)

	elapsed := time.Since(pb.start)
	var eta time.Duration
	if pb.current > 0 {
		eta = time.Duration(float64(elapsed) / float64(pb.current) * float64(pb.total-pb.current))
	}

	fmt.Printf("\r[%s] %.0f%% (%d/%d) | Tempo: %s | ETA: %s  ",
		bar,
		percent*100,
		pb.current,
		pb.total,
		formatDuration(elapsed),
		formatDuration(eta))
}

func formatDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	d -= h * time.Hour
	m := d / time.Minute
	d -= m * time.Minute
	s := d / time.Second

	if h > 0 {
		return fmt.Sprintf("%dh%dm%ds", h, m, s)
	} else if m > 0 {
		return fmt.Sprintf("%dm%ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

// Spinner representa um spinner animado
type Spinner struct {
	frames []string
	index  int
	active bool
	text   string
}

// NewSpinner cria um novo spinner
func NewSpinner(text string) *Spinner {
	return &Spinner{
		frames: []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"},
		text:   text,
	}
}

// Start inicia o spinner
func (s *Spinner) Start() {
	s.active = true
	go func() {
		for s.active {
			fmt.Printf("\r%s %s", s.frames[s.index], s.text)
			s.index = (s.index + 1) % len(s.frames)
			time.Sleep(100 * time.Millisecond)
		}
	}()
}

// Stop para o spinner
func (s *Spinner) Stop() {
	s.active = false
	fmt.Print("\r")
}

// UpdateText atualiza o texto do spinner
func (s *Spinner) UpdateText(text string) {
	s.text = text
}
