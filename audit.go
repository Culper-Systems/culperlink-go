package culperlink

import (
	"context"
	"net/http"
	"net/url"
)

// AuditLogEntry is one k-anonymised access-log record: a daily request count
// per endpoint, never PII or payload content.
type AuditLogEntry struct {
	Date         string `json:"date"`          // YYYY-MM-DD
	CustomerHash string `json:"customer_hash"` // truncated SHA-256
	Endpoint     string `json:"endpoint"`
	Count        int    `json:"count"`
	HTTPStatus   string `json:"http_status"` // "2xx" | "4xx" | "5xx"
}

// AuditLogOptions narrows AuditLog to a date range; empty is unbounded.
type AuditLogOptions struct {
	From string // inclusive, YYYY-MM-DD
	To   string // inclusive, YYYY-MM-DD
}

// AuditLog reads the k-anonymised access-log view (GET /audit/v1/access),
// scoped by the service to the session's own organisation. A Control Plane
// call; it does not bring the tunnel up.
func (c *Client) AuditLog(ctx context.Context, opts AuditLogOptions) ([]AuditLogEntry, error) {
	q := url.Values{}
	if opts.From != "" {
		q.Set("from", opts.From)
	}
	if opts.To != "" {
		q.Set("to", opts.To)
	}
	path := "/audit/v1/access"
	if enc := q.Encode(); enc != "" {
		path += "?" + enc
	}
	var entries []AuditLogEntry
	if err := c.doRequest(ctx, http.MethodGet, path, nil, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}
