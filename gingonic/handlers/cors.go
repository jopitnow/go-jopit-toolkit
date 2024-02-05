package handlers

import (
	"github.com/gin-gonic/gin"
)

func CORSMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Vary", "Origin")
		c.Writer.Header().Set("Vary", "Access-Control-Request-Method")
		c.Writer.Header().Set("Vary", "Access-Control-Request-Headers")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
