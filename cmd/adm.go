package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/patrickmn/go-cache"
	"github.com/txn2/ack"
	"github.com/txn2/micro"
	"github.com/txn2/provision"
	"go.uber.org/zap"
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

	// cache
	csh := cache.New(1*time.Minute, 10*time.Minute)
	provisionService := *provisionScheme + "://" + *provisionHost

	// check account against access key
	checkAccount := func(accountId string, accessKey provision.AccessKey) (bool, error) {

		cacheKey := accountId + accessKey.Name + accessKey.Key

		// check cache
		cacheResult, found := csh.Get(cacheKey)
		if found {
			return cacheResult.(bool), nil
		}

		url := provisionService + "/keyCheck/" + accountId

		accountKeyJson, err := json.Marshal(accessKey)
		if err != nil {
			csh.Set(cacheKey, false, cache.DefaultExpiration)
			return false, err
		}
		req, _ := http.NewRequest("POST", url, bytes.NewReader(accountKeyJson))
		res, err := server.Client.Http.Do(req)
		if err != nil {
			server.Logger.Warn(
				"Provision service request failure.",
				zap.String("url", url),
				zap.Error(err))

			csh.Set(cacheKey, false, cache.DefaultExpiration)
			return false, err
		}

		if res.StatusCode == 404 {
			csh.Set(cacheKey, false, cache.DefaultExpiration)
			return false, errors.New(accountId + " account not found.")
		}

		if res.StatusCode == 200 {
			csh.Set(cacheKey, true, cache.DefaultExpiration)
			return true, nil
		}

		csh.Set(cacheKey, false, cache.DefaultExpiration)
		return false, fmt.Errorf("got code %d from %s ", res.StatusCode, url)
	}

	accessHandler := func(c *gin.Context) {
		ak := ack.Gin(c)

		// requests for whoami account return the header value of
		// X-DCP-Account
		pa := c.Param("parentAccount")
		server.Logger.Info("Parent account", zap.String("parent_id", pa))

		if pa == "whoami" {
			hdr := c.GetHeader("X-DCP-Account")
			if hdr == "" {
				ak.SetPayloadType("ErrorMessage")
				ak.SetPayload("No X-DCP-Account header.")
				ak.GinErrorAbort(401, "E401", "X-DCP-Account header was not sent to whoami")
				return
			}

			ak.SetPayloadType("WhoAmI")
			ak.GinSend(hdr)
			c.Abort()
			return
		}

		// Check api key for parentAccount if one exists
		name, key, ok := c.Request.BasicAuth()
		if ok {
			accessKey := provision.AccessKey{
				Name: name,
				Key:  key,
			}

			ok, err := checkAccount(pa, accessKey)
			if err != nil {
				ak.SetPayloadType("ErrorMessage")
				ak.SetPayload("APIKeyCheckError")
				ak.GinErrorAbort(401, "E401", err.Error())
				return
			}

			if !ok {
				ak.SetPayloadType("ErrorMessage")
				ak.SetPayload("APIKeyCheckError")
				ak.GinErrorAbort(401, "E401", "Invalid API Key")
				return
			}

			// valid key
			return
		}

		// User token middleware
		tokenHandler := provision.UserTokenHandler()
		tokenHandler(c)

		if c.IsAborted() {
			return
		}

		// Check token if one exists
		userI, ok := c.Get("User")
		if !ok {
			ak.SetPayloadType("ErrorMessage")
			ak.SetPayload("missing user token")
			ak.GinErrorAbort(401, "E401", "UnauthorizedAccess")
			return
		}

		user := userI.(*provision.User)

		// let sysops though
		if user.Active && user.Sysop {
			return
		}

		// @TODO Check token for parentAccount

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
