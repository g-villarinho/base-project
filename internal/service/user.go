package service

import (
	"context"
	"fmt"
	"log/slog"

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
	logger   *slog.Logger
}

func NewUserService(userRepo repository.UserRepository, logger *slog.Logger) UserService {
	return &userService{
		userRepo: userRepo,
		logger:   logger.With(slog.String("service", "user")),
	}
}

func (s *userService) UpdateUser(ctx context.Context, userID uuid.UUID, name string) error {
	if err := s.userRepo.UpdateName(ctx, userID, name); err != nil {
		if err == repository.ErrUserNotFound {
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("update name: %w", err)
	}

	return nil
}

func (s *userService) GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if err == repository.ErrUserNotFound {
			return nil, domain.ErrUserNotFound
		}

		return nil, fmt.Errorf("find user by id: %w", err)
	}

	return user, nil
}
