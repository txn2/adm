package main

import (
	"flag"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/txn2/ack"
	"github.com/txn2/micro"
	"github.com/txn2/provision"
)

var (
	provisionHostEnv   = getEnv("PROVISION_HOST", "api-provision:8080")
	provisionSchemeEnv = getEnv("PROVISION_SCHEME", "http")
)

func main() {

	provisionHost := flag.String("provisionHost", provisionHostEnv, "Provision host")
	provisionScheme := flag.String("provisionScheme", provisionSchemeEnv, "Provision scheme")

	serverCfg, _ := micro.NewServerCfg("Adm")
	server := micro.NewServer(serverCfg)

	// User token middleware
	server.Router.Use(provision.UserTokenHandler())

	accessHandler := func(c *gin.Context) {
		ak := ack.Gin(c)

		userI, ok := c.Get("User")
		if !ok {
			ak.SetPayloadType("ErrorMessage")
			ak.SetPayload("missing user token")
			ak.GinErrorAbort(401, "E401", "UnauthorizedAccess")
			return
		}

		user := userI.(*provision.User)

		if user.Active && user.Sysop {
			return
		}

		ak.SetPayloadType("ErrorMessage")
		ak.SetPayload("insufficient privileges")
		ak.GinErrorAbort(401, "E401", "UnauthorizedAccess")
		return
	}

	adm := server.Router.Group("/adm/:parentAccount", accessHandler)

	adm.Any("/*any",
		server.ReverseProxy(micro.PxyCfg{
			Scheme: provisionScheme,
			Host:   provisionHost,
		}),
	)

	// run op server
	server.Run()
}

// getEnv gets an environment variable or sets a default if
// one does not exist.
func getEnv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}

	return value
}
