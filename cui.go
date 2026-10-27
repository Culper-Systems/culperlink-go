package culperlink

import (
	"context"
	"errors"
)

// CUIMarking is a Controlled Unclassified Information marking (NARA CUI
// Registry, 32 CFR Part 2002). Set on Options.Tunnel it decides the
// constraints and the geofence gateway selection applies; on a payload,
// through TagPayload, it is local metadata only.
type CUIMarking string

// The common CUI categories.
const (
	CUINone            CUIMarking = ""
	CUIBasic           CUIMarking = "CUI"
	CUIPrivacy         CUIMarking = "CUI//PRVCY"
	CUIProprietaryInfo CUIMarking = "CUI//PROPIN"
	CUIDefenseCSI      CUIMarking = "CUI//SP-CTI" // Controlled Technical Information
	CUIExportControl   CUIMarking = "CUI//SP-EXPT"
	CUINuclear         CUIMarking = "CUI//SP-NUC"
)

// IsValid reports whether m is one of the markings above.
func (m CUIMarking) IsValid() bool {
	switch m {
	case CUINone, CUIBasic, CUIPrivacy, CUIProprietaryInfo,
		CUIDefenseCSI, CUIExportControl, CUINuclear:
		return true
	}
	return false
}

// RequiresSovereignNode reports whether policy says a marking should be
// routed to a sovereign node. A local predicate for callers to branch on;
// the client does not route on it.
func (m CUIMarking) RequiresSovereignNode() bool {
	switch m {
	case CUIBasic, CUIPrivacy, CUIProprietaryInfo,
		CUIDefenseCSI, CUIExportControl, CUINuclear:
		return true
	}
	return false
}

// TagPayload encrypts payload, then records marking on the returned
// EncryptedPayload. The marking is applied after the response comes back:
// it is not sent to the service, not bound into the AEAD, and does not
// influence routing. To route by marking, set Options.Tunnel.CUIMarking.
func (c *Client) TagPayload(ctx context.Context, payload []byte, marking CUIMarking, channel string) (*EncryptedPayload, error) {
	if !marking.IsValid() {
		return nil, errors.New("culperlink: invalid CUI marking")
	}
	ep, err := c.Encrypt(ctx, payload, channel)
	if err != nil {
		return nil, err
	}
	ep.CUIMarking = string(marking)
	return ep, nil
}

// SetSovereignPool records the organisation's sovereign-node pool identifier.
// Gateway selection then offers nodes from that pool only, and a pool with
// no eligible node is ErrSovereignNodeUnavailable, never a node outside it.
// Set it before Connect or the first Data Plane call: a tunnel already up is
// not re-selected.
func (c *Client) SetSovereignPool(poolID string) {
	c.session.setSovereignPool(poolID)
}
