package utils

import (
	"encoding/base64"
	"log"
	"testing"

	"github.com/oklog/ulid"
)

func TestULID(t *testing.T) {
	id, _ := base64.StdEncoding.DecodeString("AVyA0TxXluS0fKvwyMWMLg==")
	ulid := ulid.ULID{}
	ulid.UnmarshalBinary(id)
	log.Println(id, ulid, ulid.Time())
}
