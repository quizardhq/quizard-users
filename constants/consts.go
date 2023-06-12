package constants

import "github.com/quizardhq/internal/helpers"


const (
	Active helpers.AccountStatus = iota
	Suspended
	InActive
	Banned
)