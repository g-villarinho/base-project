package model

// RevokeAllSessionsPayload represents the request body for revoking all sessions
// @name RevokeAllSessionsPayload
type RevokeAllSessionsPayload struct {
	IncludeCurrent bool `json:"include_current" example:"false"`
}
