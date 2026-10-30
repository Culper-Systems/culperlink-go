package culperlink

import (
	"fmt"
	"strings"
	"testing"
)

// TestPrintedClientsNeverCarryTheAPIKey is CULPER-460 G-11: every way a
// caller might print the options or the client leaves the API key out.
func TestPrintedClientsNeverCarryTheAPIKey(t *testing.T) {
	const key = "clk_live_PRINT_SECRET"
	opts := Options{APIKey: key, Endpoint: "https://culperlink.internal.example", Tunnel: TunnelOptions{Mode: TunnelOff}}
	c, err := NewClient(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	printed := map[string]string{}
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
		printed["Options "+verb] = fmt.Sprintf(verb, opts)
		printed["*Options "+verb] = fmt.Sprintf(verb, &opts)
		printed["*Client "+verb] = fmt.Sprintf(verb, c)
		printed["struct holding a *Client "+verb] = fmt.Sprintf(verb, struct{ C *Client }{c})
		printed["struct holding Options "+verb] = fmt.Sprintf(verb, struct{ O Options }{opts})
	}
	for name, out := range printed {
		if strings.Contains(out, key) {
			t.Errorf("%s printed the API key: %s", name, out)
		}
	}
	if !strings.Contains(fmt.Sprintf("%+v", opts), "culperlink.internal.example") {
		t.Errorf("redaction dropped the rest of the options: %+v", opts)
	}
	if opts.APIKey != key {
		t.Fatal("printing changed the caller's options")
	}
}
