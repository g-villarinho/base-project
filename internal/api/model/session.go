package model

// RevokeAllSessionsPayload represents the request body for revoking all sessions
type RevokeAllSessionsPayload struct {
	IncludeCurrent bool `json:"include_current" example:"false"`
}
