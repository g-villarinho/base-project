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
	ErrVerificationCodeNotFound = errors.New("verification code record not found")
)

type VerificationTokenRepository interface {
	Create(ctx context.Context, verificationToken *domain.VerificationToken) error
	FindByID(ctx context.Context, ID uuid.UUID) (*domain.VerificationToken, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	FindValidByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationTokenFlow) (*domain.VerificationToken, error)
	InvalidateByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationTokenFlow) error
}

type verificationCodeRepository struct {
	db *gorm.DB
}

func NewVerificationCodeRepository(db *gorm.DB) VerificationTokenRepository {
	return &verificationCodeRepository{
		db: db,
	}
}

func (r *verificationCodeRepository) Create(ctx context.Context, verificationToken *domain.VerificationToken) error {
	if err := r.db.WithContext(ctx).Create(&verificationToken).Error; err != nil {
		return err
	}

	return nil
}

func (r *verificationCodeRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.VerificationToken, error) {
	var verificationCode domain.VerificationToken
	err := r.db.WithContext(ctx).First(&verificationCode, "id = ?", ID).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrVerificationCodeNotFound
		}

		return nil, err
	}

	return &verificationCode, nil
}

func (r *verificationCodeRepository) Delete(ctx context.Context, ID uuid.UUID) error {
	err := r.db.WithContext(ctx).Delete(&domain.VerificationToken{}, "id = ?", ID).Error
	if err != nil {
		return err
	}

	return nil
}

func (r *verificationCodeRepository) FindValidByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationTokenFlow) (*domain.VerificationToken, error) {
	var verificationCode domain.VerificationToken

	err := r.db.WithContext(ctx).
		Where("user_id = ? AND flow = ? AND expires_at > ?", userID, flow, time.Now().UTC()).
		Order("created_at DESC").
		First(&verificationCode).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrVerificationCodeNotFound
		}
		return nil, err
	}

	return &verificationCode, nil
}

func (r *verificationCodeRepository) InvalidateByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationTokenFlow) error {
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND flow = ? AND expires_at > ?", userID, flow, time.Now().UTC()).
		Delete(&domain.VerificationToken{}).Error

	return err
}
