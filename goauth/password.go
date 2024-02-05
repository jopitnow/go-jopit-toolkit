package goauth

import (
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	oncePassword       sync.Once
	pwdMiddCredentials *passwordMiddleware
)

type passwordMiddleware struct {
	username string
	password string
}

func (pmw *passwordMiddleware) setPassword(pwd string) {
	pmw.password = pwd
}

func (pmw *passwordMiddleware) setUsernane(usr string) {
	pmw.username = usr
}

func PasswordMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {

		if pwdMiddCredentials.password == "" {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if pwdMiddCredentials.username == "" {
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		headerUsername := c.GetHeader("Admin-Username")
		if headerUsername == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "username is empty, please provide one")
			return
		}

		headerPassword := c.GetHeader("Admin-Password")
		if headerPassword == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, "password is empty, please provide one")
			return
		}

		if headerUsername != pwdMiddCredentials.username {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		if headerPassword != pwdMiddCredentials.password {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Set("Admin-Username", headerUsername)
		c.Next()
	}
}

func init() {
	oncePassword.Do(InitPasswordMiddleware)
}

func InitPasswordMiddleware() {

	pwdMiddCredentials = &passwordMiddleware{}

	password := os.Getenv("ADMIN_PASSWORD")
	username := os.Getenv("ADMIN_USERNAME")

	if username == "" {
		log.Println("Admin-Username is not setted in the repository missing credentuials value")
	}
	pwdMiddCredentials.setUsernane(username)

	if password == "" {
		log.Println("Admin-Password is not setted in the repository missing credentuials value")
	}

	pwdMiddCredentials.setPassword(password)
}
