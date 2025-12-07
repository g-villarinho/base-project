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
	queries *sqlc.Queries
}

func NewSessionRepository(db *sql.DB, logger *slog.Logger) SessionRepository {
	return &sessionRepository{
		queries: sqlc.New(db),
	}
}

func (r *sessionRepository) Create(ctx context.Context, session *domain.Session) error {
	err := r.queries.CreateSession(ctx, sqlc.CreateSessionParams{
		ID:         session.ID.String(),
		Token:      session.Token,
		DeviceName: session.DeviceName,
		IpAddress:  session.IPAddress,
		UserAgent:  session.UserAgent,
		ExpiresAt:  session.ExpiresAt,
		CreatedAt:  session.CreatedAt,
		UserID:     session.UserID.String(),
	})
	if err != nil {
		return fmt.Errorf("persist session: %w", err)
	}

	return nil
}

func (r *sessionRepository) FindByID(ctx context.Context, ID uuid.UUID) (*domain.Session, error) {
	row, err := r.queries.FindSessionByID(ctx, ID.String())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("find session by id: %w", err)
	}

	return r.toDomainSession(row), nil
}

func (r *sessionRepository) FindByToken(ctx context.Context, token string) (*domain.Session, error) {
	row, err := r.queries.FindSessionByToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("find session by token: %w", err)
	}

	return r.toDomainSession(row), nil
}

func (r *sessionRepository) DeleteByID(ctx context.Context, ID uuid.UUID) error {
	result, err := r.queries.DeleteSessionByID(ctx, ID.String())
	if err != nil {
		return fmt.Errorf("delete session by id: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *sessionRepository) DeleteByUserID(ctx context.Context, userID uuid.UUID) error {
	result, err := r.queries.DeleteSessionsByUserID(ctx, userID.String())
	if err != nil {
		return fmt.Errorf("delete sessions by user id: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *sessionRepository) DeleteByUserExceptID(ctx context.Context, userID, exceptID uuid.UUID) error {
	result, err := r.queries.DeleteSessionsByUserExceptID(ctx, sqlc.DeleteSessionsByUserExceptIDParams{
		UserID: userID.String(),
		ID:     exceptID.String(),
	})
	if err != nil {
		return fmt.Errorf("delete sessions by user except id: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrSessionNotFound
	}

	return nil
}

func (r *sessionRepository) FindByUserID(ctx context.Context, userID uuid.UUID) ([]domain.Session, error) {
	rows, err := r.queries.FindSessionsByUserID(ctx, sqlc.FindSessionsByUserIDParams{
		UserID:    userID.String(),
		ExpiresAt: time.Now().UTC(),
	})
	if err != nil {
		return nil, fmt.Errorf("find sessions by user id: %w", err)
	}

	sessions := make([]domain.Session, 0, len(rows))
	for _, row := range rows {
		sessions = append(sessions, *r.toDomainSession(row))
	}

	return sessions, nil
}

func (r *sessionRepository) toDomainSession(row sqlc.Session) *domain.Session {
	id, _ := uuid.Parse(row.ID)
	userID, _ := uuid.Parse(row.UserID)

	return &domain.Session{
		ID:         id,
		Token:      row.Token,
		DeviceName: row.DeviceName,
		IPAddress:  row.IpAddress,
		UserAgent:  row.UserAgent,
		ExpiresAt:  row.ExpiresAt,
		CreatedAt:  row.CreatedAt,
		UserID:     userID,
	}
}
