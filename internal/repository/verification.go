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
	db *gorm.DB
}

func NewVerificationRepository(db *gorm.DB) VerificationRepository {
	return &verificationRepository{
		db: db,
	}
}

func (r *verificationRepository) Create(ctx context.Context, verification *domain.Verification) error {
	if err := r.db.WithContext(ctx).Create(&verification).Error; err != nil {
		return err
	}

	return nil
}

func (r *verificationRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.Verification, error) {
	var verification domain.Verification
	err := r.db.WithContext(ctx).First(&verification, "id = ?", ID).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrVerificationNotFound
		}

		return nil, err
	}

	return &verification, nil
}

func (r *verificationRepository) Delete(ctx context.Context, ID uuid.UUID) error {
	err := r.db.WithContext(ctx).Delete(&domain.Verification{}, "id = ?", ID).Error
	if err != nil {
		return err
	}

	return nil
}

func (r *verificationRepository) FindValidByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) (*domain.Verification, error) {
	var verification domain.Verification

	err := r.db.WithContext(ctx).
		Where("user_id = ? AND flow = ? AND expires_at > ?", userID, flow, time.Now().UTC()).
		Order("created_at DESC").
		First(&verification).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVerificationNotFound
		}
		return nil, err
	}

	return &verification, nil
}

func (r *verificationRepository) InvalidateByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error {
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND flow = ? AND expires_at > ?", userID, flow, time.Now().UTC()).
		Delete(&domain.Verification{}).Error

	return err
}

func (r *verificationRepository) FindByToken(ctx context.Context, token string) (*domain.Verification, error) {
	var verification domain.Verification
	err := r.db.WithContext(ctx).First(&verification, "token = ?", token).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrVerificationNotFound
		}

		return nil, err
	}

	return &verification, nil
}
