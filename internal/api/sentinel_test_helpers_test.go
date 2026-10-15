package api

import (
	"encoding/base64"
	"net/url"
	"strings"
)

func containsSentinel(text, sentinel string) bool {
	forms := []string{sentinel, base64.StdEncoding.EncodeToString([]byte(sentinel)), base64.RawStdEncoding.EncodeToString([]byte(sentinel)), base64.URLEncoding.EncodeToString([]byte(sentinel)), base64.RawURLEncoding.EncodeToString([]byte(sentinel)), url.QueryEscape(sentinel), url.PathEscape(sentinel)}
	for _, v := range forms {
		if v != "" && strings.Contains(text, v) {
			return true
		}
	}
	return false
}
