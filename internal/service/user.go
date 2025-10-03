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
	logger := s.logger.With(
		slog.String("method", "UpdateUser"),
		slog.String("user_id", userID.String()),
	)

	if err := s.userRepo.UpdateName(ctx, userID, name); err != nil {
		if err == repository.ErrUserNotFound {
			logger.Warn("user not found to proceed")
			return domain.ErrUserNotFound
		}

		return fmt.Errorf("update name for userId %s: %w", userID.String(), err)
	}

	return nil
}

func (s *userService) GetUser(ctx context.Context, userID uuid.UUID) (*domain.User, error) {
	logger := s.logger.With(
		slog.String("method", "GetUser"),
		slog.String("user_id", userID.String()),
	)

	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		if err == repository.ErrUserNotFound {
			logger.Warn("user not found to proceed")
			return nil, domain.ErrUserNotFound
		}

		return nil, fmt.Errorf("find user by id %s: %w", userID.String(), err)
	}

	return user, nil
}
