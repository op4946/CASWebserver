package main

import (
	"golang.org/x/crypto/bcrypt"
	"math/big"
	"crypto/rand"
	"encoding/base64"
)

func HashPassword(plainTextPass string) (string, error) {
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(plainTextPass), bcrypt.MinCost)
	return string(passwordHash), err
}

func CheckPassword(passwordHash string, passToCheck string) error {
	err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(passToCheck))
	return err
}

// Next three functions were taken from https://gist.github.com/dopey/c69559607800d2f2f90b1b1ed4e550fb
// Licensed under the MIT license
func GenerateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}

func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)
	return base64.URLEncoding.EncodeToString(b), err
}
