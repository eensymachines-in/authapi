package handlers

// All the user route handlers here
import (
	"fmt"
	"log"
	"net/http"

	auth "github.com/eensymachines-in/auth/v2"
	ex "github.com/eensymachines-in/errx"
	"github.com/gin-gonic/gin"
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

// HandlUsrDevices : for user the devices this serves as route handelr
func HandlUsrDevices(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	val, _ := c.Get("devreg")
	dr := val.(*auth.DeviceRegColl) // we will query this
	email := c.Param("email")
	if c.Request.Method == "GET" {
		// trying to get all the devices of a certain user
		stati, err := dr.FindUserDevices(email)
		if err != nil {
			ex.DigestErr(err, c)
			return
		}
		log.Printf("user devices %v", stati)
		c.JSON(http.StatusOK, stati)
		return
	}
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
			// log.Infof("just to log the account details %v", *ud)
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "GET" {
		result := []auth.UserAccDetails{}
		// in one large dump this will pick the user accounts and dispatch them to the result
		// we need to add this new Enlist function in auth package
		if ex.DigestErr(ua.Enlist(&result), c) != 0 {
			return
		}
		c.JSON(http.StatusOK, result)
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
		details, err := ua.AccountDetails(email)
		if err != nil {
			ex.DigestErr(err, c)
			return
		}
		if details.Role < 2 {
			// Only if the user account is not of an admin
			// admin accounts cannot be deleted
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
		}
		ex.DigestErr(ex.NewErr(&ex.ErrInsuffPrivlg{}, fmt.Errorf("Trying to delete admin account %s", email), "Admin accounts are immune to deletion, will not proceed", "HandlUser/DEL"), c)
		return

	} else if c.Request.Method == "PUT" {
		// changing all the account details given the email id
		// IMP: this does not change the password of the account,
		// to change the password use the patch verb
		newDetails := &auth.UserAccDetails{}
		if c.ShouldBindJSON(newDetails) != nil {
			ex.DigestErr(ex.NewErr(&ex.ErrJSONBind{}, fmt.Errorf("Failed to read account details to be updated"), "Invalid account details to alter, check and send again", "HandlUser/PUT"), c)
			return
		}
		if ex.DigestErr(ua.UpdateAccDetails(newDetails), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "PATCH" {
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
