package main

import (
	"github.com/quizardhq/constants"
	"github.com/quizardhq/database"
	"github.com/quizardhq/internal/handlers"
	"github.com/quizardhq/internal/routes"

	"flag"
	"log"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	_ "golang.org/x/text"
)

var (
	prod = flag.Bool("prod", false, "Enable prefork in Production")
)

func main() {
	constant := constants.New()

	// Parse command-line flags
	flag.Parse()

	// Create fiber app
	app := fiber.New(fiber.Config{
		Prefork: *prod, // go run app.go -prod
	})

	app.Static("/", "./static/public")

	// Middleware
	app.Use(recover.New())
	app.Use(logger.New())
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
