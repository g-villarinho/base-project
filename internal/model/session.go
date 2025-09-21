package model

type RevokeAllSessionsPayload struct {
	IncludeCurrent bool `query:"include_current"`
}
