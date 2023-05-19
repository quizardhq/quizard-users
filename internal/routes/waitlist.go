package routes

import (
	"github.com/quizardhq/internal/handlers"
	"github.com/quizardhq/internal/repository"

	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

func registerWaitlist(router fiber.Router, db *gorm.DB) {
	waitlistRouter := router.Group("waitlist")
	waitlistRepo := repository.NewWaitlistRepository(db)
	handlers := handlers.NewWaitlistHandler(waitlistRepo)

	waitlistRouter.Post("/", handlers.WaitlistCreate)
}
