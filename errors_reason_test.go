package culperlink

import (
	"encoding/json"
	"testing"
)

// The server's error envelope carries an optional reason class on
// INVALID_PASSKEY (CULPER-468); the core's wire-shape test holds this type to
// the server's, field for field.
func TestAPIErrorDecodesTheReasonClass(t *testing.T) {
	var e APIError
	if err := json.Unmarshal([]byte(`{"code":"INVALID_PASSKEY","message":"passkey refused","reason":"sign_count_replay"}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.Reason != "sign_count_replay" {
		t.Fatalf("Reason = %q, want sign_count_replay", e.Reason)
	}
	var plain APIError
	if err := json.Unmarshal([]byte(`{"code":"RATE_LIMITED","message":"slow down","retry_after":5}`), &plain); err != nil {
		t.Fatal(err)
	}
	if plain.Reason != "" {
		t.Fatalf("Reason = %q on a code that carries none", plain.Reason)
	}
}
