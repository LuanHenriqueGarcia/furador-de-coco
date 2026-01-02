package logger

import (
	"fmt"
	"time"
)

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorWhite  = "\033[37m"
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARN
	ERROR
	SUCCESS
)

var currentLevel = INFO
var enableColors = true

func SetLevel(level Level) {
	currentLevel = level
}

func DisableColors() {
	enableColors = false
}

func colorize(color, text string) string {
	if !enableColors {
		return text
	}
	return color + text + ColorReset
}

func log(level Level, levelStr, color, format string, args ...interface{}) {
	if level < currentLevel {
		return
	}

	timestamp := time.Now().Format("15:04:05")
	prefix := fmt.Sprintf("[%s] %s", timestamp, colorize(color, levelStr))
	message := fmt.Sprintf(format, args...)
	fmt.Printf("%s %s\n", prefix, message)
}

func Debug(format string, args ...interface{}) {
	log(DEBUG, "DEBUG", ColorPurple, format, args...)
}

func Info(format string, args ...interface{}) {
	log(INFO, "INFO ", ColorCyan, format, args...)
}

func Warn(format string, args ...interface{}) {
	log(WARN, "WARN ", ColorYellow, format, args...)
}

func Error(format string, args ...interface{}) {
	log(ERROR, "ERROR", ColorRed, format, args...)
}

func Success(format string, args ...interface{}) {
	log(SUCCESS, "OK   ", ColorGreen, format, args...)
}

func Fatal(format string, args ...interface{}) {
	log(ERROR, "FATAL", ColorRed, format, args...)
	panic(fmt.Sprintf(format, args...))
}
