package version

import "testing"

func TestString(t *testing.T) {
	if got := String(); got != "0.1.0-dev" {
		t.Fatalf("String() = %q", got)
	}
}
