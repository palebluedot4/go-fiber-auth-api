package password

type Hasher interface {
	Hash(password string) (string, error)
	Verify(hashedPassword, password string) bool
}
