package handlers

import (
	"github.com/gofiber/fiber/v2"
	"gorm.io/gorm"
)

type UserHandler struct {
	database *gorm.DB
}

func NewUserHandler(db *gorm.DB) *UserHandler {
	return &UserHandler{
		database: db,
	}
}

// UserList returns a list of users
func (u *UserHandler) UserList(c *fiber.Ctx) error {

	return c.JSON(fiber.Map{
		"success": true,
	})
}

func (u *UserHandler) GetUserById(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{
		"success": true,
		"user":    nil,
	})
}

// NotFound returns custom 404 page
func NotFound(c *fiber.Ctx) error {
	return c.Status(404).SendFile("./static/private/404.html")
}
