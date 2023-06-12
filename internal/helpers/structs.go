package helpers

import "github.com/golang-jwt/jwt"

type InputCreateUser struct {
	FirstName string `json:"first_name" validate:"required"`
	LastName  string `json:"last_name" validate:"required"`
	Email     string `json:"email" validate:"required,email"`
	Password  string `json:"password" validate:"required"`
}

type OtpVerify struct {
	Token string `json:"token" validate:"required,len=5"`
	Email string `json:"email" validate:"required,email"`
}

type AccountReset struct {
	Email string `json:"email" validate:"required,email"`
}
type AuthenticateUser struct {
	Email    string `json:"email" validate:"required,email"`
	Password string `json:"password" validate:"required"`
}

type IError struct {
	Field string
	Tag   string
	Value string
}

type AuthTokenJwtClaim struct {
	Email string
	Name  string
	jwt.StandardClaims
}

type AccountStatus int
