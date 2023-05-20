package handlers

import (
	"bytes"
	"fmt"
	"log"
	"path/filepath"
	"errors"

	"github.com/quizardhq/constants"
	"github.com/quizardhq/internal/helpers"
	"github.com/quizardhq/internal/models"
	"github.com/quizardhq/internal/repository"
	"github.com/quizardhq/sendgrid"

	"github.com/gofiber/fiber/v2"
)

var (
	env = constants.New()
	ErrDbError = errors.New("something went wrong")
)

type WaitlistHandler struct {
	waitlistRepository *repository.WaitlistRepository
}

type AppError struct {
	Message string
}

func (e *AppError) Error() string {
	return e.Message
}
func NewError(message string) *AppError {
	return &AppError{
		Message: message,
	}
}

func NewWaitlistHandler(
	waitlistRepo *repository.WaitlistRepository,
) *WaitlistHandler {
	return &WaitlistHandler{
		waitlistRepository: waitlistRepo,
	}
}

type InputCreateWaitlist struct {
	Email     string `json:"email" valid:"email~Invalid Email format,required~email is required"`
	FirstName string `json:"first_name" valid:"required~first name is required"`
	LastName  string `json:"last_name" valid:"required~last name is required"`
}

func (u *WaitlistHandler) WaitlistCreate(c *fiber.Ctx) error {
	var input InputCreateWaitlist
	if err := c.BodyParser(&input); err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	err := helpers.ValidateBody(input)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	_, userExist, err := u.waitlistRepository.FindRecordByCondition("email", input.Email)
	if err != nil {
		return helpers.Dispatch500Error(c, ErrDbError)
	}

	if userExist {
		return helpers.Dispatch400Error(c, "Thou art already on the waitlist, my dear. The magic shall reveal thy fate soon.", nil)
	}

	user := &models.Waitlist{
		Email:     input.Email,
		FirstName: input.FirstName,
		LastName:  input.LastName,
	}

	if err := u.waitlistRepository.CreateRecord(user); err != nil {
		return helpers.Dispatch500Error(c, NewError("failed to create"))
	}

	go func(To InputCreateWaitlist) {
		to := sendgrid.EmailAddress{
			Name:  fmt.Sprintf("%s %s", To.FirstName, To.LastName),
			Email: To.Email,
		}

		absolutePath, err := filepath.Abs("templates/email/waitlist_create.html")
		if err != nil {
			log.Println(err)
			return
		}

		template, err := helpers.ParseTemplateFile(absolutePath)
		if err != nil {
			log.Println(err)
			return
		}

		if template == nil {
			return
		}

		messageBody := new(bytes.Buffer)
		err = template.Execute(messageBody, to)
		if err != nil {
			log.Println(err)
			return
		}

		client := sendgrid.NewClient(env.SendGridApiKey, "hello@quizardhq.com", " Quizard", "Welcome to the Quizard Waitlist: Exciting Opportunities Await!", messageBody.String())
		err = client.Send(&to)
		if err != nil {
			log.Println(err)
			return
		}
	}(input)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "Added successfully",
		"data": map[string]string{
			"id":    fmt.Sprint(user.ID),
			"email": user.Email,
		},
	})
}
