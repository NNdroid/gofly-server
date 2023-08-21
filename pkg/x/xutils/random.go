package xutils

import (
	"math/rand"
	"time"
)

func RandomString(length int) string {
	rand.NewSource(time.Now().UnixNano())
	charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var result string
	for i := 0; i < length; i++ {
		result += string(charset[rand.Intn(len(charset))])
	}
	return result
}

func RandomInt(max int) int {
	rand.NewSource(time.Now().UnixNano())
	return rand.Intn(max)
}
