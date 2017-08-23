package utils

import (
	"crypto/rand"

	"github.com/oklog/ulid"
)

//NewULID 生成新id
func NewULID() ulid.ULID {
	entropy := rand.Reader
	return ulid.MustNew(ulid.Now(), entropy)
}
