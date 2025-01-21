package goauth

import (
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
)

var (
	oncePassword       sync.Once
	pwdMiddCredentials *passwordMiddleware
)

type AdminHeaderUsr string
type AdminHeaderPwd string

const (
	valueAdminUsr                      = "Admin-Username"
	valueAdminPwd                      = "Admin-Password"
	AdminHeaderUsername AdminHeaderUsr = valueAdminUsr
	AdminHeaderPassword AdminHeaderPwd = valueAdminPwd
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

func SetContextWithAdminValues(c *gin.Context) context.Context {

	ctx := context.WithValue(c.Request.Context(), AdminHeaderUsername, c.GetHeader(valueAdminUsr)) //to do move to toolkit
	ctx = context.WithValue(ctx, AdminHeaderPassword, c.GetHeader(valueAdminPwd))                  //to do move to toolkit

	return ctx
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

func BasicAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		auth := c.GetHeader("Authorization")
		if auth == "" {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(auth, "Basic ")
		decoded, err := base64.StdEncoding.DecodeString(token)
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		pair := strings.SplitN(string(decoded), ":", 2)
		if len(pair) != 2 || !validateCredentials(pair[0], pair[1]) {
			c.Header("WWW-Authenticate", `Basic realm="Restricted"`)
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	}
}

func validateCredentials(username, password string) bool {
	return username == pwdMiddCredentials.username && password == pwdMiddCredentials.password
}
