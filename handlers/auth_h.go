package handlers

// this here is to handle all the authentication and authorization route requests

import (
	"fmt"
	"net/http"
	"os"

	auth "github.com/eensymachines-in/auth/v2"
	ex "github.com/eensymachines-in/errx"
	"github.com/gin-gonic/gin"
)

// getTknCacFromCtx : extracts the cache pointer from the context inserted by the middleware
func getTknCacFromCtx(c *gin.Context) (*auth.TokenCache, func()) {
	val, exists := c.Get("cache")
	if !exists {
		c.AbortWithStatus(http.StatusBadGateway)
		return nil, nil
	}
	tokCach := val.(*auth.TokenCache)
	if tokCach == nil {
		c.AbortWithStatus(http.StatusBadGateway)
		return nil, nil
	}
	val, _ = c.Get("cache_close")
	cacClose := val.(func())
	return tokCach, cacClose
}

// getTknPairFromCtx : when the auth header receives the bearer tokens, it would inject the same in the context
// this helper here will get that out of the context
func getTknFromCtx(c *gin.Context) *auth.JWTok {
	val, exists := c.Get("token")
	if !exists {
		c.AbortWithStatus(http.StatusUnauthorized)
		return nil
	}
	return val.(*auth.JWTok)
}

// HndlAuthrz : handles authorizations
func HndlAuthrz(c *gin.Context) {
	// +++++++++++++++++++++++++++
	// Now getting the cache handle
	tokCach, cacClose := getTknCacFromCtx(c)
	defer cacClose()
	if c.Request.Method == "GET" {
		if c.Query("refresh") == "true" {
			pair := &auth.TokenPair{}
			if ex.DigestErr(tokCach.RefreshUser(getTknFromCtx(c), pair), c) != 0 {
				return
			}
			c.JSON(http.StatusOK, pair.MakeMarshalable(os.Getenv("AUTH_SECRET"), os.Getenv("REFR_SECRET")))
			return
		}
		// Now getting the token state
		if ex.DigestErr(tokCach.TokenStatus(getTknFromCtx(c)), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "DELETE" {
		if ex.DigestErr(tokCach.LogoutToken(getTknFromCtx(c)), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	}

}

// handlAuth : login and authnetication only
func HandlAuth(c *gin.Context) {
	// +++++++++++++++++++++++++
	// Getting the database handle
	val, exists := c.Get("userreg")
	if !exists {
		c.AbortWithStatus(http.StatusBadGateway)
		return
	}
	usrRegColl, _ := val.(*auth.UserAccounts)
	if usrRegColl == nil {
		c.AbortWithStatus(http.StatusBadGateway)
		return
	}
	val, _ = c.Get("close_session")
	dbSessClose := val.(func())
	defer dbSessClose()

	// +++++++++++++++++++++++++++
	// Now getting the cache handle
	tokCach, cacClose := getTknCacFromCtx(c)
	defer cacClose()
	// ++++++++++++++++++++++++++++
	// getting the user param
	email := c.Param("email")
	if email == "" {
		c.AbortWithStatus(http.StatusBadGateway)
		return
	}
	creds := &auth.UserAcc{}
	if ex.DigestErr(c.ShouldBindJSON(creds), c) != 0 {
		c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to bind user account credentials from the request"))
		return
	}
	details, err := usrRegColl.AccountDetails(creds.Email)
	if ex.DigestErr(err, c) != 0 {
		return
	}
	creds.Role = details.Role // getting the role from the credentials in the payload
	_, err = usrRegColl.Authenticate(creds)
	if ex.DigestErr(err, c) != 0 {
		return
	} //error itself will indicate that creds have not been authenticated

	// +++++++++++++++++ now time to create tokens and udpate the cache
	tokPair := &auth.TokenPair{}
	if ex.DigestErr(tokCach.LoginUser(creds.Email, creds.Role, tokPair), c) != 0 {
		return
	}
	c.JSON(http.StatusOK, tokPair.MakeMarshalable(os.Getenv("AUTH_SECRET"), os.Getenv("REFR_SECRET")))
	return
}
