package service

import (
	"context"
	"fmt"

	"github.com/g-villarinho/user-demo/internal/domain"
	"github.com/g-villarinho/user-demo/internal/repository"
	"github.com/google/uuid"
)

type UserService interface {
	UpdateProfile(ctx context.Context, userID uuid.UUID, name string) error
}

type userService struct {
	userRepo repository.UserRepository
}


func NewUserService(userRepo repository.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) UpdateProfile(ctx context.Context, userID uuid.UUID, name string) error {
	if err := s.userRepo.UpdateName(ctx, userID, name); err != nil {
		if err == repository.ErrUserNotFound {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("update name for userId %s: %w", userID.String(), err)
	}


	return nil
}
