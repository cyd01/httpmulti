package httpmulti

import (
	"errors"
	"os"
	"regexp"
)

func isValidAddr(addr string) bool {
	regex := regexp.MustCompile(`^([a-zA-Z0-9.-]+)?:([0-9]+)$`)
	return regex.MatchString(addr)
}

func existfile(filename string) bool {
	if _, err := os.Stat(filename); errors.Is(err, os.ErrNotExist) {
		return false
	}
	return true
}
