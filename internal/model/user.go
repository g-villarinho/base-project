package model

import "github.com/google/uuid"

type UpdateProfilePayload struct {
	Name     string `json:"name" validate:"required,max=255" example:"João Silva"`
}

type ProfileResponse struct {
	ID uuid.UUID `json:"id"`
	Name string  `json:"name"`
	Email string `json:"email"`
}


