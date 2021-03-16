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
		// c.AbortWithStatus(http.StatusBadGateway)
		ex.DigestErr(ex.NewErr(&ex.ErrConnFailed{}, fmt.Errorf("No cache connection found middleware"), "One or more gateways on the server has failed", "getTknCacFromCtx"), c)
		return nil, nil
	}
	tokCach := val.(*auth.TokenCache)
	if tokCach == nil {
		ex.DigestErr(ex.NewErr(&ex.ErrConnFailed{}, fmt.Errorf("Invalid type of cache connection in middleware"), "One or more gateways on the server has failed", "getTknCacFromCtx"), c)
		// c.AbortWithStatus(http.StatusBadGateway)
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
		ex.DigestErr(ex.NewErr(&ex.ErrInsuffPrivlg{}, fmt.Errorf("No token string found in header"), "This request requires authorization, no authorization was provided", "getTknFromCtx"), c)
		// c.AbortWithStatus(http.StatusUnauthorized)
		return nil
	}
	return val.(*auth.JWTok)
}

// HndlAuthrz : handles authorizations
func HndlAuthrz(c *gin.Context) {
	// +++++++++++++++++++++++++++
	// Now getting the cache handle
	tokCach, cacClose := getTknCacFromCtx(c)
	if tokCach == nil {
		return
	}
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

// HandlAuth : login and authnetication only
func HandlAuth(c *gin.Context) {
	// +++++++++++++++++++++++++
	// Getting the database handle
	val, _ := c.Get("userreg")
	usrRegColl, _ := val.(*auth.UserAccounts)
	val, _ = c.Get("close_session")
	dbSessClose := val.(func())
	defer dbSessClose()

	// +++++++++++++++++++++++++++
	// Now getting the cache handle
	tokCach, cacClose := getTknCacFromCtx(c)
	if tokCach == nil {
		return
	}
	defer cacClose()
	// ++++++++++++++++++++++++++++
	// +++++++++ from b64UserCredsParse middleware
	e, _ := c.Get("email")
	p, _ := c.Get("passwd")
	creds := &auth.UserAcc{Email: fmt.Sprintf("%v", e), Passwd: fmt.Sprintf("%v", p)}
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
	// ahead of issue #24 - the authentication api needs to send the tokens and the account information
	tokPayload := tokPair.MakeMarshalable(os.Getenv("AUTH_SECRET"), os.Getenv("REFR_SECRET"))
	payload := map[string]interface{}{
		"auth":  tokPayload.(map[string]string)["auth"],
		"refr":  tokPayload.(map[string]string)["refr"],
		"email": details.Email,
		"role":  details.Role,
		"name":  details.Name,
	}
	c.JSON(http.StatusOK, payload)
	return
}
