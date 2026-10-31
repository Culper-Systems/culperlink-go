package culperlink

// geofence_test.go — pins this copy of the client-side geofence (CULPER-460
// G-35: geofence.go cited this file before it existed).
//
// The expected lists are written out here as fixed values, not read from the
// variables under test, so a change to either the lists or the marking rules
// fails here. The same lists are held by the Python SDK
// (sdks/python/culperlink/geofence.py) and the TypeScript SDK
// (sdks/typescript/src/geofence.ts) in the CulperLink core repository, and by
// the server's internal/routing/geofence.go.

import (
	"slices"
	"testing"
)

func TestGeofenceListsArePinned(t *testing.T) {
	wantGovCloud := []string{"us-gov-west-1", "us-gov-east-1"}
	wantITAR := []string{"CN", "RU", "IR", "KP", "SY", "CU", "VE", "BY", "MM"}
	tests := []struct {
		marking        CUIMarking
		wantCountries  []string
		wantRegions    []string
		wantDisallowed []string
	}{
		{CUINone, nil, nil, nil},
		{CUIBasic, []string{"US"}, nil, nil},
		{CUIPrivacy, []string{"US"}, nil, nil},
		{CUIProprietaryInfo, []string{"US"}, nil, nil},
		{CUIDefenseCSI, []string{"US"}, wantGovCloud, wantITAR},
		{CUIExportControl, []string{"US"}, nil, wantITAR},
		{CUINuclear, []string{"US"}, wantGovCloud, nil},
		{CUINavalReactors, []string{"US"}, wantGovCloud, nil},
		{CUIIntelligence, []string{"US"}, wantGovCloud, nil},
		{CUIExportControlled, []string{"US"}, nil, wantITAR},
		{CUIHealth, []string{"US"}, nil, nil},
		{CUILawEnforcement, []string{"US"}, nil, nil},
	}
	for _, tc := range tests {
		t.Run(string(tc.marking), func(t *testing.T) {
			g := geofenceFor(tc.marking)
			if !slices.Equal(g.allowedCountries, tc.wantCountries) ||
				!slices.Equal(g.allowedRegions, tc.wantRegions) ||
				!slices.Equal(g.disallowedCountries, tc.wantDisallowed) {
				t.Fatalf("geofenceFor(%q) = %+v", tc.marking, g)
			}
		})
	}
}

func TestGeofenceViolation(t *testing.T) {
	tests := []struct {
		name    string
		marking CUIMarking
		d       GatewayDescriptor
		want    string
	}{
		{"no marking admits anywhere", CUINone, GatewayDescriptor{Country: "CN"}, ""},
		{"basic admits a US node", CUIBasic, GatewayDescriptor{Country: "US", Region: "us-east-1"}, ""},
		{"basic refuses outside the US", CUIBasic, GatewayDescriptor{Country: "DE"}, "country not in the allowed list"},
		{"CTI refuses a proscribed country first", CUIDefenseCSI, GatewayDescriptor{Country: "CN", Region: "us-gov-west-1"}, "country on the disallowed list"},
		{"CTI refuses a commercial US region", CUIDefenseCSI, GatewayDescriptor{Country: "US", Region: "us-east-1"}, "region not in the allowed list"},
		{"CTI admits GovCloud", CUIDefenseCSI, GatewayDescriptor{Country: "US", Region: "us-gov-east-1"}, ""},
		{"export control admits a commercial US region", CUIExportControl, GatewayDescriptor{Country: "US", Region: "us-east-1"}, ""},
		{"nuclear refuses a commercial US region", CUINuclear, GatewayDescriptor{Country: "US", Region: "us-west-2"}, "region not in the allowed list"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := geofenceFor(tc.marking).violation(tc.d); got != tc.want {
				t.Fatalf("violation = %q, want %q", got, tc.want)
			}
		})
	}
}
