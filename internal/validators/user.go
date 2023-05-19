package validators

import (
	"github.com/quizardhq/internal/helpers"

	"github.com/go-playground/validator"
	"github.com/gofiber/fiber/v2"
)

var Validator = validator.New()

func ValidateRegisterUserSchema(c *fiber.Ctx) error {
	body := new(helpers.InputCreateUser)
	err := c.BodyParser(&body)
	if err != nil {
		return helpers.Dispatch400Error(c, "invalid payload", nil)
	}

	err = Validator.Struct(body)
	if err != nil {
		return helpers.SchemaError(c, err)
	}
	return c.Next()
}
