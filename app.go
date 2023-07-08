package main

import (
	"github.com/quizardhq/constants"
	"github.com/quizardhq/database"
	"github.com/quizardhq/internal/handlers"
	"github.com/quizardhq/internal/otp"
	"github.com/quizardhq/internal/routes"

	"flag"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	_ "golang.org/x/text"
)

var (
	prod = flag.Bool("prod", false, "Enable prefork in Production")
)

func main() {
	logger, err := zap.Config{
		Encoding:         "json",
		Level:            zap.NewAtomicLevelAt(zapcore.InfoLevel),
		OutputPaths:      []string{"stdout", "tmp/log.txt"},
		ErrorOutputPaths: []string{"stderr"},
		EncoderConfig:    zap.NewProductionEncoderConfig(),
	}.Build()
	if err != nil {
		panic(err)
	}
	defer func() {
		err := logger.Sync()
		if err != nil {
			// Handle the error appropriately, such as logging or returning an error
			log.Println("Failed to sync logger:", err)
		}
	}()

	constant := constants.New()
	_ = otp.NewOTPManager()

	// Parse command-line flags
	flag.Parse()

	// Create fiber app
	app := fiber.New(fiber.Config{
		Prefork: *prod, // go run app.go -prod
	})

	app.Static("/", "./static/public")

	// Middleware
	app.Use(recover.New())
	// Set the Zap logger as the Fiber logger
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("logger", logger)
		return c.Next()
	})

	app.Use(func(c *fiber.Ctx) error {

		logger := c.Locals("logger").(*zap.Logger)

		// Log request details
		logger.Info("Request received",
			zap.String("method", c.Method()),
			zap.String("path", c.Path()),
			zap.String("ip", c.IP()),
			zap.Any("headers", c.Request()),
		)

		// Proceed to the next middleware or route handler
		err := c.Next()

		// Log response details
		logger.Info("Response sent",
			zap.Int("status", c.Response().StatusCode()),
			zap.Any("headers", c.Response()),
		)

		return err
	})
	app.Use(cors.New(cors.Config{
		AllowOrigins: "http://localhost:3000,https://quizardhq.com",
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	dbConfig := database.Config{
		Host:     constant.DbHost,
		Port:     constant.DbPort,
		Password: constant.DbPassword,
		User:     constant.DbUser,
		DBName:   constant.DbName,
	}

	database.Connect(&dbConfig)

	database.RunManualMigration(database.DB)

	// Bind routes
	routes.Routes(app, database.DB)

	// Handle not founds
	app.Use(handlers.NotFound)

	port := os.Getenv("PORT")
	if port == "" {
		port = constant.Port
	}

	// Listen on port set in .env
	log.Fatal(app.Listen(":" + port))
}
