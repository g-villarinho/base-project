package repository

import (
	"context"
	"errors"

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
	DeleteByID(ctx context.Context, ID uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
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

func (r *sessionRepository) DeleteByID(ctx context.Context, ID uuid.UUID) error {
	if err := r.db.WithContext(ctx).Delete(&domain.Session{}, ID).Error; err != nil {
		return err
	}

	return nil
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	if err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&domain.Session{}).
		Error; err != nil {
		return err
	}

	return nil
}
