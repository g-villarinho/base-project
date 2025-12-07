package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/g-villarinho/base-project/internal/database/sqlc"
	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/google/uuid"
)

var (
	ErrVerificationNotFound = errors.New("verification record not found")
)

type VerificationRepository interface {
	Create(ctx context.Context, verification *domain.Verification) error
	FindByID(ctx context.Context, ID uuid.UUID) (*domain.Verification, error)
	Delete(ctx context.Context, ID uuid.UUID) error
	FindValidByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) (*domain.Verification, error)
	DeleteByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error
	FindByToken(ctx context.Context, token string) (*domain.Verification, error)
}

type verificationRepository struct {
	queries *sqlc.Queries
}

func NewVerificationRepository(db *sql.DB) VerificationRepository {
	return &verificationRepository{
		queries: sqlc.New(db),
	}
}

func (r *verificationRepository) Create(ctx context.Context, verification *domain.Verification) error {
	err := r.queries.CreateVerification(ctx, sqlc.CreateVerificationParams{
		ID:        verification.ID.String(),
		Flow:      string(verification.Flow),
		Token:     verification.Token,
		CreatedAt: verification.CreatedAt,
		ExpiresAt: verification.ExpiresAt,
		Payload:   verification.Payload,
		UserID:    verification.UserID.String(),
	})
	if err != nil {
		return fmt.Errorf("persist verification: %w", err)
	}

	return nil
}

func (r *verificationRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.Verification, error) {
	row, err := r.queries.FindVerificationByID(ctx, ID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationNotFound
		}
		return nil, fmt.Errorf("find verification by id: %w", err)
	}

	return r.toDomainVerification(row), nil
}

func (r *verificationRepository) Delete(ctx context.Context, ID uuid.UUID) error {
	result, err := r.queries.DeleteVerification(ctx, ID.String())
	if err != nil {
		return fmt.Errorf("delete verification: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrVerificationNotFound
	}

	return nil
}

func (r *verificationRepository) FindValidByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) (*domain.Verification, error) {
	row, err := r.queries.FindValidVerificationByUserIDAndFlow(ctx, sqlc.FindValidVerificationByUserIDAndFlowParams{
		UserID:    userID.String(),
		Flow:      string(flow),
		ExpiresAt: time.Now().UTC(),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationNotFound
		}
		return nil, fmt.Errorf("find valid verification by user ID and flow: %w", err)
	}

	return r.toDomainVerification(row), nil
}

func (r *verificationRepository) DeleteByUserIDAndFlow(ctx context.Context, userID uuid.UUID, flow domain.VerificationFlow) error {
	err := r.queries.DeleteVerificationsByUserIDAndFlow(ctx, sqlc.DeleteVerificationsByUserIDAndFlowParams{
		UserID:    userID.String(),
		Flow:      string(flow),
		ExpiresAt: time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("delete by user ID and flow: %w", err)
	}

	return nil
}

func (r *verificationRepository) FindByToken(ctx context.Context, token string) (*domain.Verification, error) {
	row, err := r.queries.FindVerificationByToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrVerificationNotFound
		}
		return nil, fmt.Errorf("find verification by token: %w", err)
	}

	return r.toDomainVerification(row), nil
}

func (r *verificationRepository) toDomainVerification(row sqlc.Verification) *domain.Verification {
	id, _ := uuid.Parse(row.ID)
	userID, _ := uuid.Parse(row.UserID)

	return &domain.Verification{
		ID:        id,
		Flow:      domain.VerificationFlow(row.Flow),
		Token:     row.Token,
		CreatedAt: row.CreatedAt,
		ExpiresAt: row.ExpiresAt,
		Payload:   row.Payload,
		UserID:    userID,
	}
}
