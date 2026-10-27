package culperlink

// geofence.go — the geofence, re-applied client-side.
//
// The Control Plane derives a fence from the CUI marking and enforces it when
// it builds the candidate list, so the list should already be inside it. The
// client checks anyway, against the placement each descriptor carries, before
// handing a candidate to the daemon: the fence is a compliance property of
// the payload's route, and it should not rest on one component having been
// correct — nor on which SDK the customer uses. The Python and TypeScript
// libraries hold the same three lists; geofence_test.go pins this copy.
//
// Mirrored: US only for any marking; the ITAR-proscribed list excluded for
// the export-controlled markings; GovCloud regions for the markings that need
// them. Not mirrored: what the client cannot know (the organisation's own
// country constraints and the sovereign pool's regions), which only narrow
// the server's fence, so this check never admits what the server refused.

import "slices"

var (
	usOnlyCountries = []string{"US"}
	govCloudRegions = []string{"us-gov-west-1", "us-gov-east-1"}
	itarDisallowed  = []string{"CN", "RU", "IR", "KP", "SY", "CU", "VE", "BY", "MM"}
)

// geofence is three lists, each empty meaning "no constraint on this axis".
type geofence struct {
	allowedCountries    []string
	allowedRegions      []string
	disallowedCountries []string
}

func geofenceFor(m CUIMarking) geofence {
	if m == CUINone {
		return geofence{}
	}
	g := geofence{allowedCountries: usOnlyCountries}
	if m == CUIDefenseCSI || m == CUIExportControl {
		g.disallowedCountries = itarDisallowed
	}
	if m == CUIDefenseCSI || m == CUINuclear {
		g.allowedRegions = govCloudRegions
	}
	return g
}

// violation is the reason d is outside the fence, or "" when it is inside.
func (g geofence) violation(d GatewayDescriptor) string {
	switch {
	case slices.Contains(g.disallowedCountries, d.Country):
		return "country on the disallowed list"
	case len(g.allowedCountries) > 0 && !slices.Contains(g.allowedCountries, d.Country):
		return "country not in the allowed list"
	case len(g.allowedRegions) > 0 && !slices.Contains(g.allowedRegions, d.Region):
		return "region not in the allowed list"
	}
	return ""
}
