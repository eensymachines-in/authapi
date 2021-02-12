package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/eensymachines-in/auth"
	cac "github.com/eensymachines-in/auth/cache"
	ex "github.com/eensymachines-in/errx"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v7"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2"
)

// CORS : this shall allow cross origin requests
// https://asanchez.dev/blog/cors-golang-options/
func CORS(c *gin.Context) {
	// First, we add the headers with need to enable CORS
	// Make sure to adjust these headers to your needs
	c.Header("Access-Control-Allow-Origin", "*")
	c.Header("Access-Control-Allow-Methods", "*")
	c.Header("Access-Control-Allow-Headers", "*")
	c.Header("Content-Type", "application/json")
	// Second, we handle the OPTIONS problem
	if c.Request.Method != "OPTIONS" {
		c.Next()
	} else {
		// Everytime we receive an OPTIONS request,
		// we just return an HTTP 200 Status Code
		// Like this, Angular can now do the real
		// request using any other method than OPTIONS
		c.AbortWithStatus(http.StatusOK)
	}
}

// readAuthHeader : knows how to parse header for authorization
func readAuthHeader(c *gin.Context) (cac.TokenStr, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return cac.TokenStr(""), ex.NewErr(&ex.ErrInvalid{}, nil, "Authorization header is empty", "readAuthHeader/c.GetHeader()")
	}
	parts := strings.Split(authHeader, "Bearer ")
	if len(parts) != 2 {
		return cac.TokenStr(""), ex.NewErr(&ex.ErrInvalid{}, nil, "Invalid authorization header", "readAuthHeader/strings.Split()")
	}
	tokenStr := parts[1] // we are expecting only one token at a time
	if tokenStr == "" {
		return cac.TokenStr(""), ex.NewErr(&ex.ErrInvalid{}, nil, "No authorization token found", "readAuthHeader/strings.Split()")
	}
	return cac.TokenStr(tokenStr), nil
}

// tokenParse : from the request this will parse the tokens
func tokenParse() gin.HandlerFunc {
	return func(c *gin.Context) {
		// ++++++++++++++++++
		// capturing the string token from the authorization header
		ts, err := readAuthHeader(c)
		if ex.DigestErr(err, c) != 0 {
			return
		}
		// ++++++++++++++++++
		// now converting into token object, and checking for level
		var tok *cac.JWTok
		if c.Query("refresh") == "true" {
			// only if its refresh action then we use the relevant secret
			// here we dont care about elevation since all what we are here to do is get new tokens
			tok, err = ts.Parse(os.Getenv("REFR_SECRET"))
			if ex.DigestErr(err, c) != 0 {
				return
			}
		} else {
			tok, err = ts.Parse(os.Getenv("AUTH_SECRET"))
			if ex.DigestErr(err, c) != 0 {
				return
			}
			// here since we are authorizing we check for role level too..
			// if the url does not specify the query param at all, the level check is avoided completely
			if c.Query("lvl") != "" {
				level, err := strconv.Atoi(c.Query("lvl"))
				if err != nil {
					c.AbortWithStatus(http.StatusBadRequest)
					return
				}
				if !tok.HasElevation(level) {
					c.AbortWithStatus(http.StatusForbidden)
					return
				}
			}
		}
		c.Set("token", tok)
	}
}

// Middleware to connect to redis cache
func lclCacConnect() gin.HandlerFunc {
	return func(c *gin.Context) {
		tkCac := &cac.TokenCache{Client: redis.NewClient(&redis.Options{
			Addr:     "srvredis:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})}
		if ex.DigestErr(tkCac.Ping(), c) != 0 {
			return
		}
		c.Set("cache", tkCac)
		c.Set("cache_close", func() {
			tkCac.Close()
		})
	}
}

// this one adds database collections to the context
func lclDbConnect() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := "srvmongo"
		session, err := mgo.Dial(ip)
		if err != nil {
			return
		}
		closeSession := func() {
			session.Close()
		}
		// connecting to collections and pushing it in the context
		// Incase the gateway fails and the database connection is not established we have to abort
		coll := session.DB("autolumin").C("devreg")
		if coll == nil {
			log.Error("Failed to get collection - 'devreg'")
			c.AbortWithError(http.StatusGatewayTimeout, fmt.Errorf("Failed db connection"))
			return
		}
		c.Set("devreg", &auth.DeviceRegColl{Collection: coll})

		coll = session.DB("autolumin").C("devblacklist")
		if coll == nil {
			log.Error("Failed to get collection - 'devblacklist'")
			c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed database collection connection"))
			return
		}
		c.Set("devblacklist", &auth.BlacklistColl{Collection: coll})
		// User account registration acocunt
		coll = session.DB("autolumin").C("userreg")
		if coll == nil {
			log.Error("Failed to get collection - 'userreg'")
			c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed database collection connection"))
			return
		}
		c.Set("userreg", &auth.UserAccounts{Collection: coll})
		// session close callback
		c.Set("close_session", closeSession)
		return
	}
}
