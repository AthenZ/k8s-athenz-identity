package util

import (
	"os"
)

// EnvOrDefault returns the value of the supplied variable or a default string.
func EnvOrDefault(name string, defaultValue string) string {
	v := os.Getenv(name)
	if v == "" {
		return defaultValue
	}
	return v
}
