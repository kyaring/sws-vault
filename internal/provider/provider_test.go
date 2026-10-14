package provider

import (
	"testing"
)

func TestProviderHeaders(t *testing.T) {
	h, e := Build("github-pat", "SENTINEL-VALUE-7f3a9c", "", nil)
	if e != nil || h.Get("Authorization") != "Bearer SENTINEL-VALUE-7f3a9c" {
		t.Fatal("github template incorrect", e)
	}
	h, e = Build("generic", "SENTINEL-VALUE-7f3a9c", "fake-user", map[string]string{"X-Token": "{v}", "X-User": "{username}"})
	if e != nil || h.Get("X-Token") != "SENTINEL-VALUE-7f3a9c" || h.Get("X-User") != "fake-user" {
		t.Fatal("generic template incorrect", e)
	}
	if _, e = Build("generic", "v", "", map[string]string{"X-Token": "{unknown}"}); e == nil {
		t.Fatal("unknown placeholder accepted")
	}
}
