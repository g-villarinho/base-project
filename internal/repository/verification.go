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
	ErrVerificationNotFound = errors.New("verification record not found")
)

type VerificationRepository interface {
	Create(ctx context.Context, verification *domain.Verification) error
	FindByID(ctx context.Context, ID uuid.UUID) (*domain.Verification, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	FindValidByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) (*domain.Verification, error)
	InvalidateByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error
	FindByToken(ctx context.Context, token string) (*domain.Verification, error)
}

type verificationRepository struct {
	db     *gorm.DB
	logger *slog.Logger
}

func NewVerificationRepository(db *gorm.DB, logger *slog.Logger) VerificationRepository {
	return &verificationRepository{
		db:     db,
		logger: logger.With(slog.String("repository", "verification")),
	}
}

func (r *verificationRepository) Create(ctx context.Context, verification *domain.Verification) error {
	logger := r.logger.With(
		slog.String("method", "Create"),
		slog.String("verification_id", verification.ID.String()),
	)

	if err := r.db.WithContext(ctx).Create(&verification).Error; err != nil {
		logger.Error("create verification in database", slog.String("error", err.Error()))
		return err
	}

	return nil
}

func (r *verificationRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.Verification, error) {
	logger := r.logger.With(
		slog.String("method", "FindByID"),
		slog.String("verification_id", ID.String()),
	)

	var verification domain.Verification
	err := r.db.WithContext(ctx).First(&verification, "id = ?", ID).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Warn("verification not found by id")
			return nil, ErrVerificationNotFound
		}

		logger.Error("find verification by id", slog.String("error", err.Error()))
		return nil, err
	}

	return &verification, nil
}

func (r *verificationRepository) Delete(ctx context.Context, ID uuid.UUID) error {
	logger := r.logger.With(
		slog.String("method", "Delete"),
		slog.String("verification_id", ID.String()),
	)

	err := r.db.WithContext(ctx).Delete(&domain.Verification{}, "id = ?", ID).Error
	if err != nil {
		logger.Error("failed to delete verification", slog.String("error", err.Error()))
		return err
	}

	return nil
}

func (r *verificationRepository) FindValidByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) (*domain.Verification, error) {
	logger := r.logger.With(
		slog.String("method", "FindValidByUserIDAndFlow"),
		slog.String("user_id", userID.String()),
		slog.String("flow", string(flow)),
	)

	var verification domain.Verification

	err := r.db.WithContext(ctx).
		Where("user_id = ? AND flow = ? AND expires_at > ?", userID, flow, time.Now().UTC()).
		Order("created_at DESC").
		First(&verification).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			logger.Warn("valid verification not found")
			return nil, ErrVerificationNotFound
		}
		logger.Error("find valid verification", slog.String("error", err.Error()))
		return nil, err
	}

	return &verification, nil
}

func (r *verificationRepository) InvalidateByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error {
	logger := r.logger.With(
		slog.String("method", "InvalidateByUserIDAndFlow"),
		slog.String("user_id", userID.String()),
		slog.String("flow", string(flow)),
	)

	err := r.db.WithContext(ctx).
		Where("user_id = ? AND flow = ? AND expires_at > ?", userID, flow, time.Now().UTC()).
		Delete(&domain.Verification{}).Error

	if err != nil {
		logger.Error("failed to invalidate verifications", slog.String("error", err.Error()))
	}

	return err
}

func (r *verificationRepository) FindByToken(ctx context.Context, token string) (*domain.Verification, error) {
	logger := r.logger.With(
		slog.String("method", "FindByToken"),
	)

	var verification domain.Verification
	err := r.db.WithContext(ctx).First(&verification, "token = ?", token).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			logger.Warn("verification not found by token")
			return nil, ErrVerificationNotFound
		}

		logger.Error("find verification by token", slog.String("error", err.Error()))
		return nil, err
	}

	return &verification, nil
}
