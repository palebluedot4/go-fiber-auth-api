package password_test

import (
	"testing"

	"github.com/palebluedot4/go-fiber-auth-api/pkg/password"
)

func TestPasswordHasher(t *testing.T) {
	correctPassword := "correct-secret-p@ssw0rd_123"
	incorrectPassword := "incorrect-secret-p@ssw0rd_123"

	t.Run("InsecureHashers", func(t *testing.T) {
		hashers := map[string]password.Hasher{
			"MD5":    &password.MD5Hasher{},
			"SHA256": &password.SHA256Hasher{},
		}

		for name, hasher := range hashers {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				hashedPassword, err := hasher.Hash(correctPassword)
				if err != nil {
					t.Fatalf("Hash() returned an unexpected error: %v", err)
				}
				if hashedPassword == "" {
					t.Fatal("Hash() returned an empty string, expected a hash")
				}

				if !hasher.Verify(hashedPassword, correctPassword) {
					t.Error("Verify() failed for a correct password")
				}

				if hasher.Verify(hashedPassword, incorrectPassword) {
					t.Error("Verify() succeeded for a wrong password")
				}

				t.Run("DeterministicHashIsConsistent", func(t *testing.T) {
					hashedPassword2, err := hasher.Hash(correctPassword)
					if err != nil {
						t.Fatalf("Hash() returned an unexpected error on second run: %v", err)
					}
					if hashedPassword != hashedPassword2 {
						t.Errorf("Deterministic hasher %s produced different hashes for the same password", name)
					}
				})
			})
		}
	})
}
