package hash

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	password := "mySecurePassword123!"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	if hash == "" {
		t.Fatal("HashPassword() returned empty hash")
	}

	// Verify the hash has the correct format
	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("Hash does not have correct prefix. Got: %s", hash)
	}

	// Verify hash contains all required parts
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Errorf("Hash does not have correct format. Expected 6 parts, got %d", len(parts))
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "mySecurePassword123!"
	wrongPassword := "wrongPassword"

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// Test with correct password
	err = VerifyPassword(password, hash)
	if err != nil {
		t.Errorf("VerifyPassword() failed with correct password: %v", err)
	}

	// Test with wrong password
	err = VerifyPassword(wrongPassword, hash)
	if err == nil {
		t.Error("VerifyPassword() should fail with wrong password")
	}
}

func TestVerifyPassword_LongPassword(t *testing.T) {
	// Test with password longer than 72 bytes (bcrypt's limit)
	// This verifies that Argon2id doesn't truncate like bcrypt does
	password := strings.Repeat("a", 100)
	passwordSimilar := strings.Repeat("a", 72) + strings.Repeat("b", 28)

	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// Verify correct password works
	err = VerifyPassword(password, hash)
	if err != nil {
		t.Errorf("VerifyPassword() failed with correct long password: %v", err)
	}

	// Verify similar password (same first 72 bytes) fails
	// This would succeed with bcrypt due to truncation
	err = VerifyPassword(passwordSimilar, hash)
	if err == nil {
		t.Error("VerifyPassword() should fail with similar password (bcrypt would incorrectly accept this)")
	}
}

func TestHashPassword_DifferentHashes(t *testing.T) {
	password := "mySecurePassword123!"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() failed: %v", err)
	}

	// Hashes should be different due to different salts
	if hash1 == hash2 {
		t.Error("Two hashes of the same password should be different (different salts)")
	}

	// But both should verify correctly
	if err := VerifyPassword(password, hash1); err != nil {
		t.Errorf("First hash failed to verify: %v", err)
	}
	if err := VerifyPassword(password, hash2); err != nil {
		t.Errorf("Second hash failed to verify: %v", err)
	}
}

func TestVerifyPassword_InvalidHash(t *testing.T) {
	password := "mySecurePassword123!"

	tests := []struct {
		name string
		hash string
	}{
		{"empty hash", ""},
		{"invalid format", "not-a-valid-hash"},
		{"wrong prefix", "$bcrypt$v=19$m=19456,t=2,p=1$salt$hash"},
		{"missing parts", "$argon2id$v=19$m=19456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPassword(password, tt.hash)
			if err == nil {
				t.Errorf("VerifyPassword() should fail with %s", tt.name)
			}
		})
	}
}
