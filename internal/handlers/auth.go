package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/quizardhq/constants"
	"github.com/quizardhq/internal/helpers"
	"github.com/quizardhq/internal/models"
	"github.com/quizardhq/internal/repository"

	"github.com/gofiber/fiber/v2"
	"github.com/google/go-github/v39/github"
	"golang.org/x/oauth2"
	gitOauth "golang.org/x/oauth2/github"
	googleOauth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

type AuthHandler struct {
	userRepository *repository.UserRepository
}
type AccountStatus int

const (
	Active AccountStatus = iota
	Suspended
	Banned
)

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

// registers a user
func (a *AuthHandler) Register(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	var input helpers.InputCreateUser
	if err := c.BodyParser(&input); err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	// validate email does not exist
	_, userExist, err := a.userRepository.FindUserByCondition("email", input.Email)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}
	if userExist {
		return helpers.Dispatch400Error(c, "email already exist", nil)
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
		AccountStatus: int(Suspended),
	}

	if err := a.userRepository.CreateUser(user); err != nil {
		return helpers.Dispatch500Error(c, err)
	}
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
		return helpers.Dispatch400Error(c, "invalid state value in request payload", nil)
	}
	code := c.Query("code")
	if code == "" {
		return helpers.Dispatch400Error(c, "authorization code not provided", nil)

	}

	token, err := googleoAuthConf.Exchange(c.Context(), code)
	if err != nil {
		return helpers.Dispatch500Error(c, fmt.Errorf(`unable to authenticate; err: %v`, err))
	}

	client := googleoAuthConf.Client(c.Context(), token)
	srv, err := googleOauth.NewService(c.Context(), option.WithHTTPClient(client))
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	info, err := srv.Userinfo.Get().Do()
	if err != nil {
		return helpers.Dispatch500Error(c, err)
	}

	user, userExist, err := a.userRepository.FindUserByCondition("email", info.Email)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
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
			AccountStatus: int(Active),
			LastLogin:     timenow,
		}
		if err := a.userRepository.CreateUser(user); err != nil {
			return helpers.Dispatch500Error(c, err)
		}
	} else {
		// if the user exist, we should do an update just in case the user name or profile change on google
		user.FirstName = fname[0]
		user.LastName = fname[1]
		user.AvatarURL = info.Picture
		user.LastLogin = timenow
		_, err = a.userRepository.UpdateUserByCondition("email", info.Email, user)
		if err != nil {
			return helpers.Dispatch500Error(c, err)
		}
	}

	jwtToken, err := helpers.GenerateToken(constant.JWTSecretKey, info.Email, info.Name)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
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
		return helpers.Dispatch400Error(c, "invalid state value in request payload", nil)
	}
	code := c.Query("code")
	if code == "" {
		return helpers.Dispatch400Error(c, "authorization code not provided", nil)

	}
	token, err := githubOAuthConfig.Exchange(c.Context(), code)
	if err != nil {
		return helpers.Dispatch500Error(c, fmt.Errorf(`unable to authenticate; err: %v`, err))
	}
	client := github.NewClient(githubOAuthConfig.Client(c.Context(), token))
	info, _, err := client.Users.Get(c.Context(), "")
	if err != nil {
		return c.Status(http.StatusInternalServerError).SendString(fmt.Sprintf("Failed to get user info: %v", err))
	}

	user, userExist, err := a.userRepository.FindUserByCondition("email", *info.Email)
	if err != nil {
		return helpers.Dispatch500Error(c, err)
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
			AccountStatus: int(Active),
			LastLogin:     timenow,
		}
		if err := a.userRepository.CreateUser(user); err != nil {
			return helpers.Dispatch500Error(c, err)
		}
	} else {
		user.FirstName = fname[0]
		user.LastName = fname[1]
		user.AvatarURL = info.GetAvatarURL()
		user.LastLogin = timenow

		_, err = a.userRepository.UpdateUserByCondition("email", *info.Email, user)
		if err != nil {
			return helpers.Dispatch500Error(c, err)
		}
	}

	jwtToken, err := helpers.GenerateToken(constant.JWTSecretKey, info.GetEmail(), info.GetName())
	if err != nil {
		return helpers.Dispatch500Error(c, err)
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
