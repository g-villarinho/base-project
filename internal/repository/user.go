package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/g-villarinho/base-project/internal/database/sqlc"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/google/uuid"
)

var (
	ErrUserNotFound = errors.New("user record not found")
)

type UserRepository interface {
	Create(ctx context.Context, user *domain.User) error
	ExistsByEmail(ctx context.Context, email string) (bool, error)
	VerifyEmail(ctx context.Context, ID uuid.UUID) error
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	FindByID(ctx context.Context, ID uuid.UUID) (*domain.User, error)
	UpdatePassword(ctx context.Context, ID uuid.UUID, newPasswordHash string) error
	UpdateEmail(ctx context.Context, ID uuid.UUID, newEmail string) error
	UpdateName(ctx context.Context, ID uuid.UUID, name string) error
}

type userRepository struct {
	queries *sqlc.Queries
}

func NewUserRepository(db *sql.DB, logger *slog.Logger) UserRepository {
	return &userRepository{
		queries: sqlc.New(db),
	}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	err := r.queries.CreateUser(ctx, sqlc.CreateUserParams{
		ID:               user.ID.String(),
		Name:             user.Name,
		Email:            user.Email,
		Status:           string(user.Status),
		PasswordHash:     user.PasswordHash,
		CreatedAt:        user.CreatedAt,
		UpdatedAt:        user.UpdatedAt,
		EmailConfirmedAt: user.EmailConfirmedAt,
		BlockedAt:        user.BlockedAt,
	})
	if err != nil {
		return fmt.Errorf("persist user: %w", err)
	}

	return nil
}

func (r *userRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	exists, err := r.queries.ExistsByEmail(ctx, email)
	if err != nil {
		return false, fmt.Errorf("find user by email: %w", err)
	}

	return exists, nil
}

func (r *userRepository) VerifyEmail(ctx context.Context, ID uuid.UUID) error {
	now := time.Now().UTC()

	result, err := r.queries.VerifyUserEmail(ctx, sqlc.VerifyUserEmailParams{
		UpdatedAt:        &now,
		EmailConfirmedAt: &now,
		ID:               ID.String(),
	})
	if err != nil {
		return fmt.Errorf("update user email field: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	row, err := r.queries.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	return r.toDomainUser(row), nil
}

func (r *userRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.User, error) {
	row, err := r.queries.FindUserByID(ctx, ID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("find user by id: %w", err)
	}

	return r.toDomainUser(row), nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, ID uuid.UUID, newPasswordHash string) error {
	now := time.Now().UTC()

	result, err := r.queries.UpdateUserPassword(ctx, sqlc.UpdateUserPasswordParams{
		PasswordHash: newPasswordHash,
		UpdatedAt:    &now,
		ID:           ID.String(),
	})
	if err != nil {
		return fmt.Errorf("update password fields: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *userRepository) UpdateEmail(ctx context.Context, ID uuid.UUID, newEmail string) error {
	now := time.Now().UTC()

	result, err := r.queries.UpdateUserEmail(ctx, sqlc.UpdateUserEmailParams{
		Email:     newEmail,
		UpdatedAt: &now,
		ID:        ID.String(),
	})
	if err != nil {
		return fmt.Errorf("update user email: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *userRepository) UpdateName(ctx context.Context, ID uuid.UUID, name string) error {
	now := time.Now().UTC()

	result, err := r.queries.UpdateUserName(ctx, sqlc.UpdateUserNameParams{
		Name:      name,
		UpdatedAt: &now,
		ID:        ID.String(),
	})
	if err != nil {
		return fmt.Errorf("update user name field: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

func (r *userRepository) toDomainUser(row sqlc.User) *domain.User {
	id, _ := uuid.Parse(row.ID)
	return &domain.User{
		ID:               id,
		Name:             row.Name,
		Email:            row.Email,
		Status:           domain.UserStatus(row.Status),
		PasswordHash:     row.PasswordHash,
		CreatedAt:        row.CreatedAt,
		UpdatedAt:        row.UpdatedAt,
		EmailConfirmedAt: row.EmailConfirmedAt,
		BlockedAt:        row.BlockedAt,
	}
}
