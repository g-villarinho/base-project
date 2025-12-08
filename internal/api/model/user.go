package model

import "github.com/google/uuid"

// UpdateProfilePayload represents the request body for updating user profile
// @name UpdateProfilePayload
type UpdateProfilePayload struct {
	Name string `json:"name" validate:"required,max=255" example:"João Silva"`
}

// ProfileResponse represents the user profile response
// @name ProfileResponse
type ProfileResponse struct {
	ID    uuid.UUID `json:"id" example:"550e8400-e29b-41d4-a716-446655440000"`
	Name  string    `json:"name" example:"João Silva"`
	Email string    `json:"email" example:"joao.silva@email.com"`
}


