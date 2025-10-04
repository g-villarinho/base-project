package main

import (
	"database/sql"
	"log"
	"time"

	"github.com/g-villarinho/base-project/internal/domain"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {
	db, err := gorm.Open(sqlite.Open("/app/test.db"), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to database:", err)
	}

	if err := db.AutoMigrate(&domain.User{}, &domain.Verification{}, &domain.Session{}); err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Database migrated successfully")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte("Test@123"), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal("Failed to hash password:", err)
	}

	testUser := domain.User{
		Name:             "Test User",
		Email:            "test@example.com",
		PasswordHash:     string(hashedPassword),
		Status:           domain.ActiveStatus,
		EmailConfirmedAt: sql.NullTime{Time: time.Now(), Valid: true},
		CreatedAt:        time.Now(),
	}

	var existingUser domain.User
	result := db.Where("email = ?", testUser.Email).First(&existingUser)
	if result.Error == gorm.ErrRecordNotFound {
		if err := db.Create(&testUser).Error; err != nil {
			log.Fatal("Failed to create test user:", err)
		}
		log.Println("✓ Test user created successfully!")
		log.Printf("  Email: %s\n  Password: Test@123\n", testUser.Email)
		return
	}

	log.Println("✓ Test user already exists")
}
