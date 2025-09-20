package model

import (
	"github.com/google/uuid"
)

type RegisterAccountPayload struct {
	Name     string `json:"name" validate:"required,max=255" example:"João Silva"`
	Email    string `json:"email" validate:"required,email,max=255" example:"joao.silva@email.com"`
	Password string `json:"password" validate:"min=8,max=255" example:"minhasenha123"`
}

type VerifyEmailPayload struct {
	Token uuid.UUID `query:"token" validate:"required,uuid"`
}

type LoginPayload struct {
	Email    string `json:"email" validate:"required,email,max=255" example:"joao.silva@email.com"`
	Password string `json:"password" validate:"min=8,max=255" example:"minhasenha123"`
}

type UpdatePasswordPayload struct {
	CurrentPassword string `json:"current_password" validate:"required,min=8,max=255" example:"minhasenha123"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=255" example:"novasenha456"`
}

type ForgotPasswordPayload struct {
	Email string `json:"email" validate:"required,email,max=255"`
}

type ResetPasswordPayload struct {
	Token       uuid.UUID `query:"token" validate:"required,uuid"`
	NewPassword string    `json:"new_password" validate:"required,min=8,max=255" example:"novasenha456"`
}

type RequestEmailChangePayload struct {
	NewEmail string `json:"new_email" validate:"required,email,max=255"`
}

type ConfirmEmailChangePayload struct {
	Token uuid.UUID `query:"token" validate:"required,uuid"`
}

type LoginInput struct {
	Email      string
	Password   string
	IPAddress  string
	UserAgent  string
	DeviceName string
}

type VerifyEmailInput struct {
	Token      uuid.UUID
	IPAddress  string
	UserAgent  string
	DeviceName string
}
