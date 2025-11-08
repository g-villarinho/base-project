package repository

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

var (
	ErrSessionNotFound = errors.New("session record not found")
)

type SessionRepository interface {
	Create(ctx context.Context, session *domain.Session) error
	FindByID(ctx context.Context, ID uuid.UUID) (*domain.Session, error)
	FindByToken(ctx context.Context, token string) (*domain.Session, error)
	DeleteByID(ctx context.Context, ID uuid.UUID) error
	DeleteByUserID(ctx context.Context, userID uuid.UUID) error
	DeleteByUserExceptID(ctx context.Context, userID, exceptID uuid.UUID) error
	FindByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error)
}

type sessionRepository struct {
	db *gorm.DB
}

func NewSessionRepository(db *gorm.DB, logger *slog.Logger) SessionRepository {
	return &sessionRepository{
		db: db,
	}
}

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	if err := r.db.WithContext(ctx).Create(&session).Error; err != nil {
		return fmt.Errorf("persist session: %w", err)
	}

	return nil
}

func (r *sessionRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.Session, error) {
	var session domain.Session

	if err := r.db.WithContext(ctx).First(&session, "id = ?", ID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrSessionNotFound
		}

		return nil, fmt.Errorf("find session by id: %w", err)
	}

	return &session, nil
}

func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	var session domain.Session

	if err := r.db.WithContext(ctx).First(&session, "token = ?", token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrSessionNotFound
		}

		return nil, fmt.Errorf("find session by token: %w", err)
	}

	return &session, nil
}

func (r *sessionRepository) DeleteByID(ctx context.Context, ID uuid.UUID) error {
	result := r.db.WithContext(ctx).Delete(&domain.Session{}, ID)
	if result.Error != nil {
		return fmt.Errorf("delete session by id: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&domain.Session{})

	if result.Error != nil {
		return fmt.Errorf("delete sessions by user id: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *sessionRepository) DeleteByUserExceptID(ctx context.Context, userID, exceptID uuid.UUID) error {
	result := r.db.WithContext(ctx).
		Where("user_id = ? AND id != ?", userID, exceptID).
		Delete(&domain.Session{})

	if result.Error != nil {
		return fmt.Errorf("delete sessions by user except id: %w", result.Error)
	}

	if result.RowsAffected == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *sessionRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	var sessions []domain.Session

	err := r.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC()).
		Find(&sessions).Error

	if err != nil {
		return nil, fmt.Errorf("find sessions by user id: %w", err)
	}

	return sessions, nil
}
