package handlers

// All the user route handlers here
import (
	"fmt"
	"net/http"

	auth "github.com/eensymachines-in/auth/v2"
	ex "github.com/eensymachines-in/errx"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func bindToUserAcc(c *gin.Context, result interface{}) error {
	// depending on the type of the result the client code wants this can initiate a new object
	// https://medium.com/hackernoon/today-i-learned-pass-by-reference-on-interface-parameter-in-golang-35ee8d8a848e
	// to know how to use out params of type interface{} read the above blog
	switch result.(type) {
	case *auth.UserAcc:
		ua := result.(*auth.UserAcc)
		*ua = auth.UserAcc{}
		if err := c.ShouldBindJSON(ua); err != nil {
			return ex.NewErr(&ex.ErrJSONBind{}, err, "Failed to read user account from request body", "bindToUserAcc")
		}
		result = ua
	case *auth.UserAccDetails:
		ua := result.(*auth.UserAccDetails)
		*ua = auth.UserAccDetails{}
		if err := c.ShouldBindJSON(ua); err != nil {
			return ex.NewErr(&ex.ErrJSONBind{}, err, "Failed to read user account from request body", "bindToUserAcc")
		}
		result = ua
	}
	return nil
}

// HndlUsers : handler for user acocunts as a collection and not specifc user
func HndlUsers(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	userreg, _ := c.Get("userreg")
	ua, _ := userreg.(*auth.UserAccounts)
	if c.Request.Method == "POST" {
		// post request works on not the specific account but list of all accounts
		ud := &auth.UserAccDetails{}
		if ex.DigestErr(bindToUserAcc(c, ud), c) != 0 {
			return
		}
		if ex.DigestErr(ua.InsertAccount(ud), c) != 0 {
			log.Infof("just to log the account details %v", *ud)
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	}
}

// HandlUser : handling a single user
func HandlUser(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	userreg, _ := c.Get("userreg")
	ua, _ := userreg.(*auth.UserAccounts)
	email := c.Param("email")

	if c.Request.Method == "GET" {
		// Getting details of the user account
		details, err := ua.AccountDetails(email)
		if ex.DigestErr(err, c) != 0 {
			return
		}
		c.JSON(http.StatusOK, details)
		return
	} else if c.Request.Method == "DELETE" {
		val, _ := c.Get("devreg") // getting to the devreg collection
		devreg := val.(*auth.DeviceRegColl)
		devices, err := devreg.FindUserDevices(email)
		if ex.DigestErr(err, c) != 0 {
			return
		}
		// If a user account is deleted - all the owned devices shall be blacklisted and their registrations would be deleted
		val, _ = c.Get("devblacklist")
		blckL := val.(*auth.BlacklistColl)
		for _, d := range devices {
			if ex.DigestErr(blckL.Black(&auth.Blacklist{Serial: d.Serial, Reason: "Account deleted, device is blacklisted"}), c) != 0 {
				return
			}
			if ex.DigestErr(devreg.RemoveDeviceReg(d.Serial), c) != 0 {
				return
			}
		}
		if ex.DigestErr(ua.RemoveAccount(email), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "PUT" {
		// changing all the account details given the email id
		// IMP: this does not change the password of the account,
		// to change the password use the patch verb
		newDetails := &auth.UserAccDetails{}
		if c.ShouldBindJSON(newDetails) != nil {
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to read account details to be updated"))
			return
		}
		if ex.DigestErr(ua.UpdateAccDetails(newDetails), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "PATCH" {
		// altering the password here , this has a dedicated verb attached to it
		// accPatch := &auth.UserAcc{}
		// if err := c.ShouldBindJSON(accPatch); err != nil {
		// 	log.Error(err)
		// 	c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to read account details, check and send again"))
		// 	return
		// }
		// incase of a patch we are now getting this from the middleware
		userEmail, _ := c.Get("email")
		passwd, _ := c.Get("passwd") // we have extracted the email
		accPatch := &auth.UserAcc{Email: fmt.Sprintf("%v", userEmail), Passwd: fmt.Sprintf("%v", passwd)}
		if ex.DigestErr(ua.UpdateAccPasswd(accPatch), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	}
}
