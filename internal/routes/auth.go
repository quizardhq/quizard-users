package routes

import (
	"github.com/quizardhq/internal/handlers"
	"github.com/quizardhq/internal/repository"
	"github.com/quizardhq/internal/validators"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func registerAuth(router fiber.Router, db *gorm.DB) {
	authRouter := router.Group("auth")
	userRepo := repository.NewUserRepository(db)
	handler := handlers.NewAuthHandler(userRepo)

	authRouter.Post("/register", validators.ValidateRegisterUserSchema, handler.Register)
	authRouter.Post("/", validators.ValidateLoginUser, handler.Authenticate)
	authRouter.Get("/google/callback", handler.GoogleOauthCallback)
	authRouter.Get("/google", handler.GoogleOauth)
	authRouter.Get("/github/callback", handler.GithubOauthCallback)
	authRouter.Get("/github", handler.GithubOauth)
	authRouter.Post("/otp/verify", validators.ValidateOTPVerifySchema, handler.OtpVerify)
	authRouter.Post("/account/reset", validators.ValidateAccountResetScheme, handler.AccountReset)
	authRouter.Post("/account/reset/otp/verify", validators.ValidateOTPVerifySchema, handler.AccountResetOtpVerify)
}
