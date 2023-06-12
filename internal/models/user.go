package models

import "github.com/quizardhq/internal/helpers"

type User struct {
	ID            uint   `gorm:"primarykey"`
	FirstName     string `json:"first_name"`
	LastName      string `json:"last_name"`
	Email         string `json:"email"`
	Password      string `json:"password"`
	AvatarURL     string `json:"avatar_url"`
	LastLogin     string `json:"last_login"`
	IP            string `json:"ip"`
	UserId        string `json:"user_id" validate:"required"`
	AccountStatus helpers.AccountStatus    `json:"account_status" validate:"required"`
}

type Waitlist struct {
	Email     string `json:"email"`
	ID        uint   `gorm:"primarykey"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}
