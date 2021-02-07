package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/eensymachines-in/auth"
	ex "github.com/eensymachines-in/errx"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2"
)

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

// hndlUsers : handler for user acocunts as a collection and not specifc user
func hndlUsers(c *gin.Context) {
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
func handlUser(c *gin.Context) {
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
		accPatch := &auth.UserAcc{}
		if err := c.ShouldBindJSON(accPatch); err != nil {
			log.Error(err)
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to read account details, check and send again"))
			return
		}
		if ex.DigestErr(ua.UpdateAccPasswd(accPatch), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	}
}

// handlAuth : handles login, logout and sends back token as a reponse
func handlAuth(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	userreg, _ := c.Get("userreg")
	ua, _ := userreg.(*auth.UserAccounts)
	action := c.Query("action")
	if action == "" {
		log.Error("No 'qry' query param found in the url")
		c.AbortWithStatus(http.StatusMethodNotAllowed)
		return
	}
	if action == "login" {
		creds := &auth.UserAcc{}
		if c.ShouldBindJSON(creds) != nil {
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to read account details to be inserted"))
			return
		}
		_, err := ua.Authenticate(creds)
		if ex.DigestErr(err, c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	}
	// this has to send the new tokens as well

}

func init() {
	// log.SetFormatter(&log.JSONFormatter{})
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
	log.SetReportCaller(true)
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
}
func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	// devices group
	devices := r.Group("/devices")
	devices.Use(lclDbConnect())

	devices.POST("", handlDevices)          // when creating new registrations
	devices.GET("/:serial", handlDevices)   // when getting existing registrations
	devices.PATCH("/:serial", handlDevices) // when modifying existing registration

	// Users group
	users := r.Group("/users")
	users.Use(lclDbConnect())

	users.POST("", hndlUsers)

	users.GET("/:email", handlUser)
	users.DELETE("/:email", handlUser)
	users.PUT("/:email", handlUser)
	users.PATCH("/:email", handlUser)

	auths := r.Group("/auth")
	auths.Use(lclDbConnect())
	auths.POST("", handlAuth)

	log.Fatal(r.Run(":8080"))
}
