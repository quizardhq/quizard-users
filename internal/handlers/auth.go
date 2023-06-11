package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	neturl "net/url"
	"strings"
	"time"
	"unicode"

	"github.com/quizardhq/constants"
	"github.com/quizardhq/internal/helpers"
	"github.com/quizardhq/internal/models"
	"github.com/quizardhq/internal/otp"
	"github.com/quizardhq/internal/repository"
	"github.com/quizardhq/sendgrid"

	"github.com/gofiber/fiber/v2"
	"github.com/google/go-github/v39/github"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	gitOauth "golang.org/x/oauth2/github"
	googleOauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type AuthHandler struct {
	userRepository *repository.UserRepository
}

func NewAuthHandler(
	userRepo *repository.UserRepository,
) *AuthHandler {
	return &AuthHandler{
		userRepository: userRepo,
	}
}

var (
	constant = constants.New()
	// Google OAuth 2.0 configuration
	googleoAuthConf = &oauth2.Config{
		ClientID:     constant.GoogleClientID,
		ClientSecret: constant.GoogleClientSecret,
		RedirectURL:  fmt.Sprintf("%s/auth/google/callback", constant.OAuthRedirectBaseURL),
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://accounts.google.com/o/oauth2/auth",
			TokenURL: "https://oauth2.googleapis.com/token",
		},
	}
	// Github OAuth 2.0 configuration
	githubOAuthConfig = &oauth2.Config{
		ClientID:     constant.GithubClientID,
		ClientSecret: constant.GithubClientSecret,
		RedirectURL:  fmt.Sprintf("%s/auth/github/callback", constant.OAuthRedirectBaseURL),
		Scopes:       []string{"user:email"},
		Endpoint:     gitOauth.Endpoint,
	}
)

func (a *AuthHandler) AccountResetOtpVerify(c *fiber.Ctx) error {
	var input helpers.OtpVerify
	if err := c.BodyParser(&input); err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	user, err := a.findUserOrError(input.Email)

	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	input.Token = strings.Map(unicode.ToUpper, input.Token)
	valid := otp.OTPManage.VerifyOTP(input.Email, input.Token)

	if !valid {
		return helpers.Dispatch500Error(c, NewError("invalid/expired token"))
	}
	c.Status(http.StatusOK)
	jwtToken, err := helpers.GenerateToken(constant.JWTSecretKey, user.Email, user.FirstName+" "+user.LastName)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	return c.JSON(fiber.Map{
		"success": true,
		"message": "otp confirmed successfully",
		"data": map[string]string{
			"jwt": jwtToken,
		},
	})

}

func (a *AuthHandler) AccountReset(c *fiber.Ctx) error {
	var input helpers.AccountReset
	if err := c.BodyParser(&input); err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	user, userExist, err := a.userRepository.FindUserByCondition("email", input.Email)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	otpToken, err := otp.OTPManage.GenerateOTP(input.Email, 5*time.Minute)

	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	if userExist {
		go sendPasswordResetEmail(user, otpToken)
	}
	return c.JSON(fiber.Map{
		"success": userExist,
		"message": "account reset",
		"data":    nil,
	})
}

func sendPasswordResetEmail(user *models.User, otpToken string) {
	to := sendgrid.EmailAddress{
		Name:  fmt.Sprintf("%s %s", user.FirstName, user.LastName),
		Email: user.Email,
	}

	type OTP struct {
		Otp  string
		Name string
	}

	messageBody, err := helpers.ParseTemplateFile("account_reset.html", OTP{Otp: otpToken, Name: fmt.Sprintf("%s %s", user.FirstName, user.LastName)})
	if err != nil {
		log.Println(err)
		return
	}

	client := sendgrid.NewClient(env.SendGridApiKey, "hello@quizardhq.com", "Quizard", "Complete your password reset request", messageBody)
	err = client.Send(&to)
	if err != nil {
		log.Println(err)
		return
	}
}

/*
Verify Email Address using OTP
*/
func (a *AuthHandler) OtpVerify(c *fiber.Ctx) error {
	var input helpers.OtpVerify
	if err := c.BodyParser(&input); err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	user, userExist, err := a.userRepository.FindUserByCondition("email", input.Email)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	if !userExist {
		return helpers.Dispatch400Error(c, "invalid account", nil)
	}

	input.Token = strings.Map(unicode.ToUpper, input.Token)
	valid := otp.OTPManage.VerifyOTP(input.Email, input.Token)

	if !valid {
		return helpers.Dispatch500Error(c, NewError("invalid/expired token"))
	}

	user.AccountStatus = Active
	user.IP = c.IP()

	user, err = a.userRepository.UpdateUserByCondition("email", input.Email, user)
	if err != nil {
		return helpers.Dispatch400Error(c, "something went wrong", err)
	}

	c.Status(http.StatusOK)
	jwtToken, err := helpers.GenerateToken(constant.JWTSecretKey, user.Email, user.FirstName+" "+user.LastName)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	go func(To *models.User) {
		to := sendgrid.EmailAddress{
			Name:  fmt.Sprintf("%s %s", To.FirstName, To.LastName),
			Email: To.Email,
		}

		messageBody, err := helpers.ParseTemplateFile("welcome.html", to)
		if err != nil {
			log.Println(err)
			return
		}

		client := sendgrid.NewClient(env.SendGridApiKey, "hello@quizardhq.com", "Quizard", "🎉 Welcome to Quizard: Unleash the Magic of Knowledge and Fun!", messageBody)
		err = client.Send(&to)
		if err != nil {
			log.Println(err)
			return
		}
	}(user)

	return c.JSON(fiber.Map{
		"success": true,
		"message": "authenticated successfully",
		"data": map[string]string{
			"jwt": jwtToken,
		},
	})
}

func (a *AuthHandler) Authenticate(c *fiber.Ctx) error {
	var input helpers.AuthenticateUser
	if err := c.BodyParser(&input); err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	user, userExist, err := a.userRepository.FindUserByCondition("email", input.Email)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	if !userExist {
		return helpers.Dispatch400Error(c, "invalid account credentials", nil)
	}

	hashedPassword := []byte(user.Password)
	plainPassword := []byte(input.Password)
	err = bcrypt.CompareHashAndPassword(hashedPassword, plainPassword)

	if err != nil {
		return helpers.Dispatch400Error(c, "email and password does not match", nil)
	}

	if err != nil {
		return helpers.Dispatch400Error(c, "something went wrong", err)
	}

	// check if account is active
	if user.AccountStatus == (constants.Suspended) {
		return helpers.Dispatch400Error(c, "account suspended", err)
	}

	if user.AccountStatus == (constants.Banned) {
		return helpers.Dispatch400Error(c, "account banned", err)
	}
	
		if user.AccountStatus == (constants.InActive) {
		return helpers.Dispatch400Error(c, "account not activated", err)
	}

	// update last login and ip
	time, err := helpers.TimeNow("Africa/Lagos")
	user.LastLogin = time
	user.IP = c.IP()

	if err != nil {
		return helpers.Dispatch400Error(c, "something went wrong", err)
	}
	_, err = a.userRepository.UpdateUserByCondition("email", user.Email, user)
	if err != nil {
		return helpers.Dispatch400Error(c, "something went wrong", err)
	}
	jwtToken, err := helpers.GenerateToken(constant.JWTSecretKey, user.Email, user.FirstName+" "+user.LastName)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	c.Status(http.StatusOK)
	return c.JSON(fiber.Map{
		"success": true,
		"message": "authenticated successfully",
		"data": map[string]string{
			"jwt": jwtToken,
		},
	})

}

func (a *AuthHandler) findUserOrError(email string) (user *models.User, err error) {
	user, userExist, err := a.userRepository.FindUserByCondition("email", email)
	if err != nil {
		return nil, err
	}
	if !userExist {
		return nil, NewError("user not found")
	}
	return user, nil
}

// registers a user
func (a *AuthHandler) Register(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	var input helpers.InputCreateUser
	if err := c.BodyParser(&input); err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	userFound, err := a.findUserOrError(input.Email)

	if userFound != nil && err == nil {
		return helpers.Dispatch500Error(c, NewError("user already registered"))
	}

	hash, err := helpers.HashPassword(input.Password)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	// create record
	user := &models.User{
		FirstName:     input.FirstName,
		LastName:      input.LastName,
		Email:         input.Email,
		Password:      hash,
		UserId:        helpers.GenerateUUID(),
		AccountStatus: constants.InActive,
		IP: c.IP(),
	}

	if err := a.userRepository.CreateUser(user); err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	go func(To *models.User, otp string) {
		to := sendgrid.EmailAddress{
			Name:  fmt.Sprintf("%s %s", To.FirstName, To.LastName),
			Email: To.Email,
		}

		type OTP struct {
			Otp string
		}

		messageBody, err := helpers.ParseTemplateFile("otp.html", OTP{Otp: otp})
		if err != nil {
			log.Println(err)

			return
		}

		client := sendgrid.NewClient(env.SendGridApiKey, "hello@quizardhq.com", "Quizard Support", "Complete Your Registration with the OTP Code", messageBody)
		err = client.Send(&to)
		if err != nil {
			log.Println(err)
			return
		}
	}(user, otpToken)

	c.Status(http.StatusCreated)
	return c.JSON(fiber.Map{
		"success": true,
		"message": "register user successfully",
		"data": map[string]string{
			"id":    fmt.Sprint(user.ID),
			"email": user.Email,
		},
	})
}

func (a *AuthHandler) GoogleOauthCallback(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")

	state := c.FormValue("state")

	if state != c.Cookies("oauthstate") {
		c.Set("error", "invalid state value in request payload")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}
	code := c.Query("code")
	if code == "" {
		c.Set("error", "authorization code not provided")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}

	token, err := googleoAuthConf.Exchange(c.Context(), code)
	if err != nil {
		c.Set("error", "error exhanging code for token: "+err.Error())
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}

	client := googleoAuthConf.Client(c.Context(), token)
	srv, err := googleOauth.NewService(c.Context(), option.WithHTTPClient(client))
	if err != nil {
		c.Set("error", "failed to create google auth client")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}

	info, err := srv.Userinfo.Get().Do()
	if err != nil {
		c.Set("error", "failed to get user info")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}

	user, userExist, err := a.userRepository.FindUserByCondition("email", info.Email)
	if err != nil {
		c.Set("error", "failed to get user info")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}
	fname := strings.Split(info.Name, " ")
	timenow, _ := helpers.TimeNow("Africa/Lagos")

	if !userExist {

		// create account if email not exist
		user = &models.User{
			FirstName:     fname[0],
			LastName:      fname[1],
			Email:         info.Email,
			Password:      "",
			AvatarURL:     info.Picture,
			UserId:        helpers.GenerateUUID(),
			AccountStatus: (constants.Active),
			LastLogin:     timenow,
		}
		if err := a.userRepository.CreateUser(user); err != nil {
			c.Set("error", "failed to create user record")
			c.Status(http.StatusPermanentRedirect)
			return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
		}
	} else {
		// if the user exist, we should do an update just in case the user name or profile change on google
		user.FirstName = fname[0]
		user.LastName = fname[1]
		user.AvatarURL = info.Picture
		user.LastLogin = timenow

		_, err = a.userRepository.UpdateUserByCondition("email", info.Email, user)
		if err != nil {
			c.Set("error", "failed to update user record")
			c.Status(http.StatusPermanentRedirect)
			return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
		}
	}

	jwtToken, err := helpers.GenerateToken(constant.JWTSecretKey, info.Email, info.Name)
	if err != nil {
		c.Set("error", "failed to generate auth tokn")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}

	c.Status(http.StatusPermanentRedirect)
	c.Set("token", jwtToken)
	c.Set("user_id", fmt.Sprint(user.UserId))
	c.Set("user_email", user.Email)
	c.Set("user_name", user.FirstName)

	return c.Redirect(constant.ClientOauthRedirectURL)
}

func (a *AuthHandler) GoogleOauth(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	state := base64.StdEncoding.EncodeToString(b)
	url := googleoAuthConf.AuthCodeURL(state, oauth2.AccessTypeOffline)
	decodedURL, err := neturl.QueryUnescape(url)

	if err != nil {
		c.Status(http.StatusBadRequest)
		return c.JSON(fiber.Map{
			"success": false,
			"message": err.Error(),
		})
	}
	c.Cookie(&fiber.Cookie{Name: "oauthstate", Value: state})
	c.Status(http.StatusAccepted)
	return c.JSON(fiber.Map{
		"success": true,
		"message": "google oauth",
		"data": map[string]string{
			"url": decodedURL,
		},
	})
}

func (a *AuthHandler) GithubOauthCallback(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")

	state := c.FormValue("state")
	if state != c.Cookies("oauthstate") {
		c.Set("error", "invalid state value in request payload")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}
	code := c.Query("code")
	if code == "" {
		c.Set("error", "authorization code not provided")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}
	token, err := githubOAuthConfig.Exchange(c.Context(), code)
	if err != nil {
		c.Set("error", "error exhanging code for token: "+err.Error())
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}
	client := github.NewClient(githubOAuthConfig.Client(c.Context(), token))
	info, _, err := client.Users.Get(c.Context(), "")
	if err != nil {
		c.Set("error", "failed to get user info")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}

	user, userExist, err := a.userRepository.FindUserByCondition("email", *info.Email)
	if err != nil {
		c.Set("error", "failed to get user info")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}
	fname := strings.Split(info.GetName(), " ")
	timenow, _ := helpers.TimeNow("Africa/Lagos")

	if !userExist {
		// create account if email not exist
		user = &models.User{
			FirstName:     fname[0],
			LastName:      fname[1],
			Email:         info.GetEmail(),
			Password:      "",
			AvatarURL:     info.GetAvatarURL(),
			UserId:        helpers.GenerateUUID(),
			AccountStatus: (constants.Active),
			LastLogin:     timenow,
		}
		if err := a.userRepository.CreateUser(user); err != nil {
			c.Set("error", "failed to create user record")
			c.Status(http.StatusPermanentRedirect)
			return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
		}
	} else {
		user.FirstName = fname[0]
		user.LastName = fname[1]
		user.AvatarURL = info.GetAvatarURL()
		user.LastLogin = timenow

		_, err = a.userRepository.UpdateUserByCondition("email", *info.Email, user)
		if err != nil {
			c.Set("error", "failed to update user record")
			c.Status(http.StatusPermanentRedirect)
			return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
		}
	}

	jwtToken, err := helpers.GenerateToken(constant.JWTSecretKey, info.GetEmail(), info.GetName())
	if err != nil {
		c.Set("error", "failed to generate auth tokn")
		c.Status(http.StatusPermanentRedirect)
		return c.Redirect(fmt.Sprintf(`%s?error=authentication_failed`, constant.ClientOauthRedirectURL))
	}

	c.Status(http.StatusPermanentRedirect)
	c.Set("token", jwtToken)
	c.Set("user_id", fmt.Sprint(user.UserId))
	c.Set("user_email", user.Email)
	c.Set("user_name", user.FirstName)

	return c.Redirect(constant.ClientOauthRedirectURL)
}

func (a *AuthHandler) GithubOauth(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	state := base64.StdEncoding.EncodeToString(b)
	url := githubOAuthConfig.AuthCodeURL(state)
	c.Cookie(&fiber.Cookie{Name: "oauthstate", Value: state})
	c.Status(http.StatusTemporaryRedirect)
	return c.JSON(fiber.Map{
		"success": true,
		"message": "github oauth login",
		"data": map[string]string{
			"url": url,
		},
	})
}
