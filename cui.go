package culperlink

import (
	"context"
	"errors"
)

// CUIMarking is a Controlled Unclassified Information marking as the NARA
// CUI Registry spells it (32 CFR Part 2002). Set on Options.Tunnel it is sent
// with gateway selection and decides the constraints and the geofence; on a
// payload, the service decides the marking the payload is sealed under and
// binds it into the ciphertext's associated data, so a marking stripped or
// changed later fails decryption.
//
// Each organization may have a default marking, set by the installation's
// operator. Every payload is sealed under at least that default: a request
// may raise it and can never lower it. Encrypt sends no marking, so the
// default applies; TagPayload sends one. The marking applied comes back on
// EncryptedPayload.CUIMarking, and Decrypt sends it back.
type CUIMarking string

// The nineteen markings the service recognizes. Use these constants rather
// than hardcoding strings.
const (
	CUINone             CUIMarking = ""
	CUIBasic            CUIMarking = "CUI"
	CUIPrivacy          CUIMarking = "CUI//PRVCY"
	CUIProprietaryInfo  CUIMarking = "CUI//PROPIN"
	CUIDefenseCSI       CUIMarking = "CUI//SP-CTI" // Controlled Technical Information
	CUIExportControl    CUIMarking = "CUI//SP-EXPT"
	CUINuclear          CUIMarking = "CUI//SP-NUC"
	CUINavalReactors    CUIMarking = "CUI//SP-NNPI"
	CUIIntelligence     CUIMarking = "CUI//SP-INTEL"
	CUILawEnforcement   CUIMarking = "CUI//SP-LEI"
	CUIExportControlled CUIMarking = "CUI//SP-ECI"
	CUIFinancial        CUIMarking = "CUI//SP-FIN"
	CUIProcurement      CUIMarking = "CUI//SP-PROC"
	CUIGeodetic         CUIMarking = "CUI//SP-GP"
	CUICritical         CUIMarking = "CUI//SP-CRIT"
	CUITax              CUIMarking = "CUI//SP-TAX"
	CUIStatistical      CUIMarking = "CUI//SP-STAT"
	CUIStudentRecords   CUIMarking = "CUI//SP-FERPA"
	CUIHealth           CUIMarking = "CUI//SP-HLTH"
	CUILegal            CUIMarking = "CUI//SP-LEGL"
)

// IsValid reports whether m is one the service recognizes. Unknown markings
// are refused here rather than sent.
func (m CUIMarking) IsValid() bool {
	switch m {
	case CUINone, CUIBasic, CUIPrivacy, CUIProprietaryInfo, CUIDefenseCSI, CUIExportControl,
		CUINuclear, CUINavalReactors, CUIIntelligence, CUILawEnforcement, CUIExportControlled,
		CUIFinancial, CUIProcurement, CUIGeodetic, CUICritical, CUITax, CUIStatistical,
		CUIStudentRecords, CUIHealth, CUILegal:
		return true
	}
	return false
}

// RequiresSovereignNode reports whether the marking's default routing
// requires a sovereign node: the eight high-sensitivity Specified
// categories. An organization's operator can override a marking's routing;
// the service applies the override, and this local predicate does not know
// it.
func (m CUIMarking) RequiresSovereignNode() bool {
	switch m {
	case CUIDefenseCSI, CUIExportControl, CUINuclear, CUINavalReactors,
		CUIIntelligence, CUILawEnforcement, CUIExportControlled, CUICritical:
		return true
	}
	return false
}

// TagPayload encrypts payload with marking as the request's CUI marking
// (the cui_marking body field). The service seals the payload under the
// stronger of marking and the organization's default, binds it into the
// associated data, and reports it in the returned EncryptedPayload's
// CUIMarking — which may therefore be stronger than marking. A marking the
// service cannot compare with the default (a different category of the same
// strength) is a VALIDATION_ERROR.
//
// An empty marking is Encrypt: the organization's default applies.
func (c *Client) TagPayload(ctx context.Context, payload []byte, marking CUIMarking, channel string) (*EncryptedPayload, error) {
	if !marking.IsValid() {
		return nil, errors.New("culperlink: invalid CUI marking")
	}
	return c.encrypt(ctx, payload, channel, marking)
}

// SetSovereignPool records the organization's sovereign-node pool identifier.
// Gateway selection then offers nodes from that pool only, and a pool with
// no eligible node is ErrSovereignNodeUnavailable, never a node outside it.
// Set it before Connect or the first Data Plane call: a tunnel already up is
// not re-selected.
func (c *Client) SetSovereignPool(poolID string) {
	c.session.setSovereignPool(poolID)
}
