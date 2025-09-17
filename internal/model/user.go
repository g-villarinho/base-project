package model

type UpdateProfilePayload struct {
	Name     string `json:"name" validate:"required,max=255" example:"João Silva"`
}



