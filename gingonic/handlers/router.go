/**
* @author mnunez
 */

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/gzip"
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
	"github.com/jopitnow/go-jopit-toolkit/goauth"
	"github.com/jopitnow/go-jopit-toolkit/goutils/apierrors"
	"github.com/jopitnow/go-jopit-toolkit/goutils/logger"
	"github.com/jopitnow/go-jopit-toolkit/telemetry"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

var production bool = os.Getenv("GO_ENVIRONMENT") == "production"

var ApiName string = ""

func DefaultJopitRouter() *gin.Engine {
	return CustomJopitRouter(JopitRouterConfig{})
}

func CustomJopitRouter(conf JopitRouterConfig) *gin.Engine {

	router := gin.New()

	if conf.DisableCancellationOnClientDisconnect {
		router.Use(func(c *gin.Context) {
			c.Request = c.Request.WithContext(context.Background())
			c.Next()
		})
	}
	if conf.EnableResponseCompressionSupport {
		router.Use(gzip.Gzip(gzip.DefaultCompression))
	}
	if !conf.DisablePprof {
		pprof.Register(router)
	}
	if !conf.DisableHeaderForwarding {
		router.Use(HeaderForwarding())
	}
	if !conf.DisableSwagger {
		router.GET(fmt.Sprintf("%s/swagger/*any", ApiName), goauth.BasicAuth(), ginSwagger.WrapHandler(swaggerFiles.Handler))
	}
	if !conf.DisableCORS {
		router.Use(CORSMiddleware())
	}
	if !production {
		router.Use(gin.Logger())
	}
	if !conf.DisableCommonApiFilter {
		router.Use(CommonAPiFilter(!conf.DisableCommonApiFilterErrorLog))
	}
	if !conf.DisableMetrics {
		router.Use(telemetry.MetricsMiddleware())
	}
	if !conf.DisableTracer {
		router.Use(otelgin.Middleware(ApiName + "-service"))
	}
	if !conf.DisableLogs {
		router.Use(logger.LoggerGrafanaMiddleware())
	}

	router.NoRoute(noRouteHandler)
	return router
}

type JopitRouterConfig struct {
	DisableCommonApiFilter           bool
	DisablePprof                     bool
	EnableResponseCompressionSupport bool
	DisableHeaderForwarding          bool
	DisableSwagger                   bool

	// DisableCommonApiFilterErrorLog tells the Common Api Filter to omit logging the URI in error handling.
	// This is useful when some params or query params are private data, like tokens.
	DisableCommonApiFilterErrorLog bool

	// DisableCancellationOnClientDisconnect tells the server to detach the
	// c.Request.Context() from the incoming TCP connection. If set to false
	// then the client closing the connection does not cancels the context.
	// The default behavior from Go is to cancel the request context if it can
	// ensure that there's no one on the other side to read the response.
	DisableCancellationOnClientDisconnect bool
	DisableCORS                           bool
	DisableTracer                         bool
	DisableLogs                           bool
	DisableMetrics                        bool
}

func noRouteHandler(c *gin.Context) {
	c.JSON(http.StatusNotFound, apierrors.NewApiError(fmt.Sprintf("Resource %s not found.", c.Request.URL.Path), fmt.Sprintf("Resource %s not found.", c.Request.URL.Path), http.StatusNotFound, apierrors.CauseList{}))
}

func AddResponseExpiration(time time.Duration, c *gin.Context) {
	var roundTime int = int(time.Seconds())
	c.Writer.Header()["Cache-Control"] = []string{fmt.Sprintf("max-age=%v,stale-while-revalidate=%v, stale-if-error=%v", roundTime, roundTime/2, roundTime*2)}
}
