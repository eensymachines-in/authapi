package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	b64 "encoding/base64"

	auth "github.com/eensymachines-in/auth/v2"
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
func readAuthHeader(c *gin.Context, authfield string, hdrValRead func(string) error) error {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return ex.NewErr(&ex.ErrInvalid{}, nil, "Authorization header is empty", "readAuthHeader/c.GetHeader()")
	}
	// Please see the " " after authfield, do not include from client code
	parts := strings.Split(authHeader, " ") // Bearer or Basic depending on if its token or the credentials
	if len(parts) != 2 {
		return ex.NewErr(&ex.ErrInvalid{}, nil, "Invalid authorization header", "readAuthHeader/strings.Split()")
	}
	if parts[1] == "" {
		return ex.NewErr(&ex.ErrInvalid{}, nil, "No authorization token found", "readAuthHeader/strings.Split()")
	}
	return hdrValRead(parts[1]) // this function is customizable by the middle ware function
	// Incase of token parse this is a simple TokenStr conversion
	// while when its credentials - user:passwd after base64 decoding
}

// b64UserCredsParse :here we parse in user credentials from the request
// Incase the email or password is empty this will respond with 401 and not the expected 400
// 401 makes more sense when we are authenticating it but 400 makes more sense when we are patching the password
func b64UserCredsParse() gin.HandlerFunc {
	return func(c *gin.Context) {
		// ++++++++++++++++++
		// Capturing the user account credentials encoded b64 format from
		var email, passwd string
		err := readAuthHeader(c, "Basic", func(val string) error {
			v, err := b64.StdEncoding.DecodeString(val)
			if err != nil {
				return ex.NewErr(&ex.ErrInvalid{}, err, "Error reading the encrypted credentials", "b64UserCredsParse/readAuthHeader")
			}
			lump := strings.Split(string(v), ":")
			email = lump[0]
			passwd = lump[1]
			return nil
		})
		if ex.DigestErr(err, c) != 0 {
			return
		}
		if email == "" || passwd == "" {
			// ++++++++++ incase the readAuthHeader read out empty creds
			ex.DigestErr(ex.NewErr(&ex.ErrLogin{}, err, "Invalid credentials in the request authorization", "b64UserCredsParse/readAuthHeader"), c)
			return
		}
		// ++++++++++++ user email and password are all set and ready to go
		c.Set("email", email)
		c.Set("passwd", passwd)
		log.Infof("Email %s Passwd %s", email, passwd)
	}
}

// tokenParse : from the request this will parse the tokens
func tokenParse() gin.HandlerFunc {
	return func(c *gin.Context) {
		// ++++++++++++++++++
		// capturing the string token from the authorization header
		var ts auth.TokenStr
		err := readAuthHeader(c, "Bearer", func(val string) error {
			ts = auth.TokenStr(val)
			return nil
		})
		if ex.DigestErr(err, c) != 0 {
			return
		}
		// ++++++++++++++++++
		// now converting into token object, and checking for level
		var tok *auth.JWTok
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
					ex.DigestErr(ex.NewErr(&ex.ErrInsuffPrivlg{}, fmt.Errorf("Role of the user does not have sufficient elevation"), "Insufficient privileges to perform this action", "tokenParse/HasElevation"), c)
					return
				}
			}
		}
		c.Set("token", tok)
	}
}

// verifyUser : this shall follow the tokenParse and then checks to see if the user in the token is same as the one in the param
// this is vital when it comes to modification of user accouts, only the user himself should be allowed to change details
func verifyUser() gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get("token")
		if !exists || val == nil {
			ex.DigestErr(ex.NewErr(&ex.ErrInsuffPrivlg{}, fmt.Errorf("No authorization token found on the request that mandates it"), "This request needs authorization. Login again", "verifyUser/exists"), c)
			return
		}
		tok := val.(*auth.JWTok)
		if !(tok.User == c.Param("email")) {
			ex.DigestErr(ex.NewErr(&ex.ErrLogin{}, fmt.Errorf("Token owner mismatches request param"), "There seems to be an issue with your authorization. You are advised to logout and login again", "verifyUser"), c)
			return
		}
	}
}

// verifyRole : this shall follow the tokenParse and will check if the token has the minimum required elevation
func verifyRole(elevation int) gin.HandlerFunc {
	return func(c *gin.Context) {
		val, exists := c.Get("token")
		if !exists || val == nil {
			ex.DigestErr(ex.NewErr(&ex.ErrInsuffPrivlg{}, fmt.Errorf("No authorization token found on the request that mandates it"), "This request needs authorization. Login again using admin role", "verifyRole/exists"), c)
			return
		}
		tok := val.(*auth.JWTok)
		if !tok.HasElevation(elevation) {
			ex.DigestErr(ex.NewErr(&ex.ErrInsuffPrivlg{}, fmt.Errorf("Role of the user does not have sufficient elevation"), "Insufficient privileges to perform this action", "verifyRole/HasElevation"), c)
			return
		}
	}
}

// Middleware to connect to redis cache
func lclCacConnect() gin.HandlerFunc {
	return func(c *gin.Context) {
		tkCac := &auth.TokenCache{Client: redis.NewClient(&redis.Options{
			Addr:     "srvredis:6379",
			Password: "", // no password set
			DB:       0,  // use default DB
		})}
		err := tkCac.Ping()
		if err != nil {
			ex.DigestErr(ex.NewErr(&ex.ErrConnFailed{}, err, "Server failed to connect to one of its services. Hang in till one of our admins fixes it", "lclCacConnect"), c)
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
			ex.DigestErr(ex.NewErr(&ex.ErrConnFailed{}, fmt.Errorf("Failed to connect to autolumin database"), "Server failed to connect to one of its services. Hang in till one of our admins fixes it", "lclDbConnect:autolumin/devreg"), c)
			// log.Error("Failed to get collection - 'devreg'")
			// c.AbortWithError(http.StatusGatewayTimeout, fmt.Errorf("Failed db connection"))
			return
		}
		c.Set("devreg", &auth.DeviceRegColl{Collection: coll})

		coll = session.DB("autolumin").C("devblacklist")
		if coll == nil {
			ex.DigestErr(ex.NewErr(&ex.ErrConnFailed{}, fmt.Errorf("Failed to connect to autolumin database"), "Server failed to connect to one of its services. Hang in till one of our admins fixes it", "lclDbConnect:autolumin/devblacklist"), c)
			// log.Error("Failed to get collection - 'devblacklist'")
			// c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed database collection connection"))
			return
		}
		c.Set("devblacklist", &auth.BlacklistColl{Collection: coll})
		// User account registration acocunt
		coll = session.DB("autolumin").C("userreg")
		if coll == nil {
			ex.DigestErr(ex.NewErr(&ex.ErrConnFailed{}, fmt.Errorf("Failed to connect to autolumin database"), "Server failed to connect to one of its services. Hang in till one of our admins fixes it", "lclDbConnect:autolumin/userreg"), c)
			return
		}
		c.Set("userreg", &auth.UserAccounts{Collection: coll})
		// session close callback
		c.Set("close_session", closeSession)
		return
	}
}
