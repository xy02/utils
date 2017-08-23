package utils

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"log"
	"testing"
)

func TestCheckMac(t *testing.T) {
	var passwordKey = []byte("shanghai sysolution")
	password := []byte("user password")
	encrypted := hmac.New(sha256.New, passwordKey).Sum(password)
	encrypted2 := hmac.New(sha1.New, passwordKey).Sum(password)
	log.Println(encrypted)
	log.Println(encrypted2)
	mac := hmac.New(sha256.New, passwordKey)
	mac.Write(password)
	data := mac.Sum(nil)
	log.Println(len(data), len(encrypted))
	if !CheckMAC(password, encrypted, passwordKey) {
		t.Error("diff")
	}
}
