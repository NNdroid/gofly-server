package utils

import (
	"errors"
	"os"
)

func IsFileExists(filepath string) bool {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return false
	}
	return true
}

func ReadFile(filepath string) ([]byte, error) {
	if !IsFileExists(filepath) {
		return nil, errors.New("ReadFile: " + filepath + " is not found!")
	}
	dat, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	return dat, nil
}

func WriteToFile(filepath string, context []byte) error {
	return os.WriteFile(filepath, context, 0644)
}

func ExistsFile(filepath string) bool {
	_, err := os.Stat(filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

func GetBaseDirPath() string {
	str, _ := os.Getwd()
	return str
}

func IsDir(path string) bool {
	s, err := os.Stat(path)
	if err != nil {
		return false
	}
	return s.IsDir()
}

func IsFile(path string) bool {
	return !IsDir(path)
}
