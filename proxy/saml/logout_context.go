package saml

import "time"

// LogoutContext stores temporary state for a logout flow.
// This follows the same stateless philosophy as AuthRequest,
// storing minimal information only during the logout process.
type LogoutContext struct {
	ID                string          // Unique logout session ID
	OriginType        string          // "sp" or "idp" - who initiated the logout
	OriginID          string          // Entity ID of logout initiator
	TargetID          string          // Entity ID of logout target
	RelayState        string          // Original relay state to be preserved
	CreatedAt         time.Time       // For cleanup of expired contexts
	LogoutRequestID   string          // Original logout request ID for tracking
	ProcessedRequests map[string]bool // Track processed request IDs to prevent replay
}
