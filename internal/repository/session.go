package repository

import (
	"context"
	"errors"
	"time"

	"github.com/g-villarinho/user-demo/internal/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrSessionNotFound = errors.New("session record not found")
)

type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
  FindByID(ctx context.Context, ID uuid.UUID) (*domain.Session, error)
	RevokeByUserID(ctx context.Context, userID uuid.UUID) error
	Revoke(ctx context.Context, ID uuid.UUID) error
}

type sessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB) SessionRepository {
	return &sessionRepository{
		db: db,
	}
}

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	if err := r.db.WithContext(ctx).Create(&session).Error; err != nil {
		return err
	}

	return nil
}

func (r *sessionRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.Session, error) {
	var session domain.Session

	if err := r.db.WithContext(ctx).First(&session, "id = ?", ID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrSessionNotFound
		}

		return nil, err
	}

	return &session, nil
}

func (r *sessionRepository) RevokeByUserID(ctx context.Context, userID uuid.UUID) error {
	now := time.Now().UTC()

	updates := map[string]any{
		"revoked_at": now,
		"updated_at": now,
	}

	err := r.db.WithContext(ctx).
	  Model(&domain.Session{}).
		Where("user_id = ? AND revoked_at IS NOT NULL", userID).
		Updates(updates).Error

	if err != nil {
		return err
	}

	return nil	
}

func (r *sessionRepository) Revoke(ctx context.Context, ID uuid.UUID) error {
	now := time.Now().UTC()

	updates := map[string]any{
		"revoked_at": now,
		"updated_at": now,
	}

	result := r.db.WithContext(ctx).
	  Model(&domain.Session{}).
		Where("id = ? AND revoked_at IS NOT NULL", ID).
		Updates(updates)

	if result.Error != nil {
		return result.Error
	}

	if result.RowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil	
}

