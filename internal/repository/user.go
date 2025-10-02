package repository

import (
	"context"
	"errors"
	"time"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
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
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return &userRepository{
		db: db,
	}
}

func (r *userRepository) Create(ctx context.Context, user *domain.User) error {
	if err := r.db.WithContext(ctx).Create(&user).Error; err != nil {
		return nil
	}

	return nil
}

func (r *userRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&domain.User{}).
		Where("email = ?", email).
		Count(&count).Error

	if err != nil {
		return false, err
	}

	return count > 0, nil
}

func (r *userRepository) VerifyEmail(ctx context.Context, ID uuid.UUID) error {
	now := time.Now().UTC()

	updates := map[string]any{
		"status":             domain.ActiveStatus,
		"updated_at":         now,
		"email_confirmed_at": now,
	}

	result := r.db.WithContext(ctx).Model(&domain.User{}).
		Where("id = ?", ID).
		Updates(updates)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (r *userRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).First(&user, "email = ?", email).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (r *userRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).First(&user, "id = ?", ID).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	return &user, nil
}

func (r *userRepository) UpdatePassword(ctx context.Context, ID uuid.UUID, newPasswordHash string) error {
	updates := map[string]any{
		"password_hash": newPasswordHash,
		"updated_at":    time.Now().UTC(),
	}

	result := r.db.WithContext(ctx).Model(&domain.User{}).
		Where("id = ?", ID).
		Updates(updates)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (r *userRepository) UpdateEmail(ctx context.Context, ID uuid.UUID, newEmail string) error {
	updates := map[string]any{
		"email":      newEmail,
		"updated_at": time.Now().UTC(),
	}

	result := r.db.WithContext(ctx).Model(&domain.User{}).
		Where("id = ?", ID).
		Updates(updates)

	if result.Error != nil {
		return result.Error
	}

	return nil
}

func (r *userRepository) UpdateName(ctx context.Context, ID uuid.UUID, name string) error {
	updates := map[string]any{
		"name":       name,
		"updated_at": time.Now().UTC(),
	}

	result := r.db.WithContext(ctx).Model(&domain.User{}).
		Where("id = ?", ID).
		Updates(updates)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrUserNotFound
	}

	return nil
}
