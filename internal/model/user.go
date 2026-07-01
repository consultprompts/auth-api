package model

import "time"

type User struct {
	ID            string
	Email         string
	PasswordHash  string
	EmailVerified bool
	Status        string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
