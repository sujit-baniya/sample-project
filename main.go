package main

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/template/html"
	"github.com/sujit-baniya/crypt"
	"github.com/sujit-baniya/session"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"log"
)

type Login struct {
	Email string `json:"email" form:"email"`
	Password string `json:"password" form:"password"`
}

type User struct {
	ID uint `json:"id" gorm:"id"`
	Email string `json:"email" gorm:"email"`
	Status string `json:"status" gorm:"status"`
}

type Credential struct {
	ID uint `json:"id" gorm:"id"`
	UserID string `json:"user_id" gorm:"user_id"`
	V string `json:"v" gorm:"column:v;type:bytea"`
}

func main() {
	engine := html.New("./web/views", ".html")
	app := fiber.New(fiber.Config{Views: engine})

	app.Get("/", func (c *fiber.Ctx) error {
		return c.Render("index", fiber.Map{})
	})

	app.Get("/login", func (c *fiber.Ctx) error {
		user, _ := session.User(c)
		if user != nil {
			return c.Redirect("/restricted")
		}
		return c.Render("login", fiber.Map{})
	})

	app.Post("/login", func (c *fiber.Ctx) error {
		var login Login
		var user User
		var credential Credential
		c.BodyParser(&login)
		err := DB.Find(&user, "email = ?", login.Email).Error
		if err != nil {
			fmt.Println(err)
			return c.Redirect("/login")
		}
		if user.Status != "ACTIVE" {
			fmt.Println("Not Active")
			return c.Redirect("/login")
		}
		err = DB.Find(&credential, "user_id = ?", user.ID).Error
		if err != nil {
			fmt.Println(err)
			return c.Redirect("/login")
		}
		matched, err := crypt.MatchHash(login.Password, credential.V)
		if err != nil {
			fmt.Println(err)
			return c.Redirect("/login")
		}
		if matched {
			err = session.SetKeys(c, fiber.Map{
				"user": user,
			})
			fmt.Println(err)
			err = session.Save(c)
			fmt.Println(err)
			fmt.Println(session.Get(c, "user"))
		}
		return c.Redirect("/restricted")
	})
	app.Get("/restricted", func(c *fiber.Ctx) error {
		user, err := session.User(c)
		if err != nil || user == nil {
			fmt.Println(err)
			return c.JSON("Restricted")
		}
		return c.JSON(user)
	})
	log.Fatal(app.Listen(":3000"))
}

func dbAccess() *gorm.DB {
	dsn := "host=localhost user=postgres password=postgres dbname=verify port=5432 sslmode=disable TimeZone=Asia/Kathmandu"
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		panic(err)
	}
	return db
}

func initSession() {
	session.Default(session.Config{
		Driver:         "memory",
		RegisterTypes: []interface{}{
			User{},
		},
	})
}

var DB *gorm.DB
func init() {
	DB = dbAccess()
	initSession()
}
