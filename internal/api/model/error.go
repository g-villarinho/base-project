package model

// ProblemJSON represents RFC 7807 Problem Details for HTTP APIs
// @name ProblemJSON
type ProblemJSON struct {
	Type     string                 `json:"type" example:"https://developer.mozilla.org/pt-BR/docs/Web/HTTP/Reference/Status/400"`
	Title    string                 `json:"title" example:"Bad Request"`
	Status   int                    `json:"status" example:"400"`
	Detail   string                 `json:"detail,omitempty" example:"The verification token is invalid or has expired"`
	Instance string                 `json:"instance,omitempty" example:"/auth/verify-email"`
	Code     string                 `json:"code,omitempty" example:"INVALID_TOKEN"`
	Errors   map[string]interface{} `json:"errors,omitempty"`
}
