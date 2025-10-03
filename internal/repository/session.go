package repository

import (
	"context"
	"errors"
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
	db     *gorm.DB
	logger *slog.Logger
}

func NewSessionRepository(db *gorm.DB, logger *slog.Logger) SessionRepository {
	return &sessionRepository{
		db:     db,
		logger: logger.With(slog.String("repository", "session")),
	}
}

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	logger := r.logger.With(
		slog.String("method", "Create"),
		slog.String("session_id", session.ID.String()),
	)

	if err := r.db.WithContext(ctx).Create(&session).Error; err != nil {
		logger.Error("create session in database", slog.String("error", err.Error()))
		return err
	}

	return nil
}

func (r *sessionRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.Session, error) {
	logger := r.logger.With(
		slog.String("method", "FindByID"),
		slog.String("session_id", ID.String()),
	)

	var session domain.Session

	if err := r.db.WithContext(ctx).First(&session, "id = ?", ID).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Warn("session not found by id")
			return nil, ErrSessionNotFound
		}

		logger.Error("find session by id", slog.String("error", err.Error()))
		return nil, err
	}

	return &session, nil
}

func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	logger := r.logger.With(
		slog.String("method", "FindByToken"),
	)

	var session domain.Session

	if err := r.db.WithContext(ctx).First(&session, "token = ?", token).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Warn("session not found by token")
			return nil, ErrSessionNotFound
		}

		logger.Error("failed to find session by token", slog.String("error", err.Error()))
		return nil, err
	}

	return &session, nil
}

func (r *sessionRepository) DeleteByID(ctx context.Context, ID uuid.UUID) error {
	logger := r.logger.With(
		slog.String("method", "DeleteByID"),
		slog.String("session_id", ID.String()),
	)

	if err := r.db.WithContext(ctx).Delete(&domain.Session{}, ID).Error; err != nil {
		logger.Error("failed to delete session by id", slog.String("error", err.Error()))
		return err
	}

	return nil
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	logger := r.logger.With(
		slog.String("method", "DeleteByUserID"),
		slog.String("user_id", userID.String()),
	)

	result := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Delete(&domain.Session{})

	if result.Error != nil {
		logger.Error("failed to delete sessions by user id", slog.String("error", result.Error.Error()))
		return result.Error
	}

	return nil
}

func (r *sessionRepository) DeleteByUserExceptID(ctx context.Context, userID, exceptID uuid.UUID) error {
	logger := r.logger.With(
		slog.String("method", "DeleteByUserExceptID"),
		slog.String("user_id", userID.String()),
		slog.String("except_id", exceptID.String()),
	)

	result := r.db.WithContext(ctx).
		Where("user_id = ? AND id != ?", userID, exceptID).
		Delete(&domain.Session{})

	if result.Error != nil {
		logger.Error("delete sessions by user except id", slog.String("error", result.Error.Error()))
		return result.Error
	}

	return nil
}

func (r *sessionRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	logger := r.logger.With(
		slog.String("method", "FindByUserID"),
		slog.String("user_id", userID.String()),
	)

	var sessions []domain.Session

	if err := r.db.WithContext(ctx).
		Where("user_id = ? AND expires_at > ?", userID, time.Now().UTC()).
		Find(&sessions).
		Error; err != nil {
		logger.Error("failed to find sessions by user id", slog.String("error", err.Error()))
		return nil, err
	}

	return sessions, nil
}
