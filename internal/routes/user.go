package routes

import (
	"github.com/quizardhq/internal/handlers"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func registerUser(router fiber.Router, db *gorm.DB) {
	userRouter := router.Group("users")
	handler := handlers.NewUserHandler(db)

	userRouter.Get("/profile", handler.GetUserById)
}
