package service

import (
	"context"
	"fmt"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
)

type UserService interface {
	UpdateUser(ctx context.Context, userID uuid.UUID, name string) error
	GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error)
}

type userService struct {
	userRepo repository.UserRepository
}

func NewUserService(userRepo repository.UserRepository) UserService {
	return &userService{
		userRepo: userRepo,
	}
}

func (s *userService) UpdateUser(ctx context.Context, userID uuid.UUID, name string) error {
	if err := s.userRepo.UpdateName(ctx, userID, name); err != nil {
		if err == repository.ErrUserNotFound {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("update name for userId %s: %w", userID.String(), err)
	}

	return nil
}

func (s *userService) GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}

		return nil, fmt.Errorf("find user by id %s: %w", userID.String(), err)
	}

	return user, nil
}
