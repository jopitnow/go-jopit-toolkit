package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jopitnow/go-jopit-toolkit/goauth"
	"github.com/jopitnow/go-jopit-toolkit/goutils/apierrors"
	"github.com/jopitnow/go-jopit-toolkit/tracing"
)

func JopitAuth(scopes []string) gin.HandlerFunc {
	return JopitAuthWithOptions(scopes)
}

// JopitAuthWithOptions returns an authentication middleware with options.
//
// This function creates the JopitAuth middleware with non-standard authorization options.
// These options typically weaken the authorization.
// Use this function ONLY when you fully understand the consequences of of such options. Otherwise use JopitAuth.
func JopitAuthWithOptions(scopes []string, opts ...goauth.AuthOption) gin.HandlerFunc {
	return func(c *gin.Context) {
		if err := authenticateRequest(c.Request, scopes, opts...); err != nil {
			c.Abort()
			c.JSON(err.(apierrors.ApiError).Status(), err)
		}
	}
}

func authenticateRequest(r *http.Request, scopes []string, opts ...goauth.AuthOption) error {
	if err := goauth.AuthenticateRequestWithOptions(r, opts...); err != nil {
		return err
	}

	return nil
}

func HeaderForwarding() gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx := tracing.ContextFromRequest(c.Request)
		c.Request = c.Request.WithContext(ctx)
	}
}
