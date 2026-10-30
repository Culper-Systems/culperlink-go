package culperlink

import (
	"context"
	"errors"
)

// ErrAuditLogNotServed is AuditLog's answer, always.
//
// No CulperLink installation serves an audit view to an SDK credential. The
// auditor views are at /api/v1/audit/v1/* on the installation's operator
// console, behind an operator's login, which an SDK session token is not and
// cannot become. AuditLog used to GET Options.Endpoint + "/audit/v1/access"
// with the session token, a path every installation answers 404 on, and its
// test faked that path; it now refuses before making any request, so a
// caller learns where the views are instead of meeting a 404. The method and
// its types stay so that an SDK-authenticated view, if one is ever served,
// has its client surface waiting; until then it is gated off.
var ErrAuditLogNotServed = errors.New("culperlink: no installation serves an audit log to an SDK credential; " +
	"the auditor views are at /api/v1/audit/v1/* on the operator console, behind an operator's login")

// AuditLogEntry is one row of the access-log view as this library once
// expected it. Retained, unused, with AuditLog; see ErrAuditLogNotServed.
type AuditLogEntry struct {
	Date         string `json:"date"`          // YYYY-MM-DD
	CustomerHash string `json:"customer_hash"` // truncated SHA-256
	Endpoint     string `json:"endpoint"`
	Count        int    `json:"count"`
	HTTPStatus   string `json:"http_status"` // "2xx" | "4xx" | "5xx"
}

// AuditLogOptions narrows AuditLog to a date range. Retained with AuditLog;
// see ErrAuditLogNotServed.
type AuditLogOptions struct {
	From string // inclusive, YYYY-MM-DD
	To   string // inclusive, YYYY-MM-DD
}

// AuditLog returns ErrAuditLogNotServed and makes no request: no installation
// serves an audit view to an SDK credential. See ErrAuditLogNotServed.
func (c *Client) AuditLog(context.Context, AuditLogOptions) ([]AuditLogEntry, error) {
	if c.IsClosed() {
		return nil, ErrClientClosed
	}
	return nil, ErrAuditLogNotServed
}
