package service

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/g-villarinho/base-project/internal/domain"
	"github.com/g-villarinho/base-project/internal/mocks"
	"github.com/g-villarinho/base-project/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func setupUserService(t *testing.T) (*userService, *mocks.UserRepositoryMock) {
	t.Helper()
	userRepoMock := mocks.NewUserRepositoryMock(t)
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	service := NewUserService(userRepoMock, logger).(*userService)
	return service, userRepoMock
}

func TestUserService_UpdateUser(t *testing.T) {
	t.Run("should update user name successfully when user exists", func(t *testing.T) {
		service, userRepoMock := setupUserService(t)
		ctx := context.Background()
		userID := uuid.New()
		name := "John Doe"

		userRepoMock.On("UpdateName", ctx, userID, name).Return(nil)

		err := service.UpdateUser(ctx, userID, name)

		assert.NoError(t, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return domain error when user is not found", func(t *testing.T) {
		service, userRepoMock := setupUserService(t)
		ctx := context.Background()
		userID := uuid.New()
		name := "John Doe"

		userRepoMock.On("UpdateName", ctx, userID, name).Return(repository.ErrUserNotFound)

		err := service.UpdateUser(ctx, userID, name)

		assert.Error(t, err)
		assert.Equal(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails", func(t *testing.T) {
		service, userRepoMock := setupUserService(t)
		ctx := context.Background()
		userID := uuid.New()
		name := "John Doe"
		repoErr := errors.New("database error")

		userRepoMock.On("UpdateName", ctx, userID, name).Return(repoErr)

		err := service.UpdateUser(ctx, userID, name)

		assert.Error(t, err)
		assert.NotEqual(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})
}

func TestUserService_GetUser(t *testing.T) {
	t.Run("should return user when user exists", func(t *testing.T) {
		service, userRepoMock := setupUserService(t)
		ctx := context.Background()
		userID := uuid.New()
		expectedUser := &domain.User{
			ID:    userID,
			Name:  "John Doe",
			Email: "john@example.com",
		}

		userRepoMock.On("FindByID", ctx, userID).Return(expectedUser, nil)

		user, err := service.GetUser(ctx, userID)

		assert.NoError(t, err)
		assert.Equal(t, expectedUser, user)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return domain error when user is not found", func(t *testing.T) {
		service, userRepoMock := setupUserService(t)
		ctx := context.Background()
		userID := uuid.New()

		userRepoMock.On("FindByID", ctx, userID).Return(nil, repository.ErrUserNotFound)

		user, err := service.GetUser(ctx, userID)

		assert.Error(t, err)
		assert.Nil(t, user)
		assert.Equal(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})

	t.Run("should return error when repository fails", func(t *testing.T) {
		service, userRepoMock := setupUserService(t)
		ctx := context.Background()
		userID := uuid.New()
		repoErr := errors.New("database connection failed")

		userRepoMock.On("FindByID", ctx, userID).Return(nil, repoErr)

		user, err := service.GetUser(ctx, userID)

		assert.Error(t, err)
		assert.Nil(t, user)
		assert.NotEqual(t, domain.ErrUserNotFound, err)
		userRepoMock.AssertExpectations(t)
	})
}
