package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/eensymachines-in/auth"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2"
)

// hndlUsers : handler for user acocunts as a collection and not specifc user
func hndlUsers(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	userreg, _ := c.Get("userreg")
	ua, _ := userreg.(*auth.UserAccounts)
	if c.Request.Method == "POST" {
		// post request works on not the specific account but list of all accounts
		userAccount := &auth.UserAccDetails{}
		if c.ShouldBindJSON(userAccount) != nil {
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to read account details to be inserted"))
			return
		}
		if err := ua.InsertAccount(userAccount); err != nil {
			if _, ok := err.(auth.ErrInvalid); ok {
				c.AbortWithError(http.StatusBadRequest, err)
				return
			} else if _, ok := err.(auth.ErrDuplicate); ok {
				c.AbortWithError(http.StatusBadRequest, err)
				return
			} else if _, ok := err.(auth.ErrQueryFailed); ok {
				c.AbortWithError(http.StatusBadGateway, err)
				return
			}
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
		if err != nil {
			if _, ok := err.(auth.ErrInvalid); ok {
				c.AbortWithError(http.StatusBadRequest, err)
				return
			} else if _, ok := err.(auth.ErrNotFound); ok {
				c.AbortWithError(http.StatusBadRequest, err)
				return
			} else if _, ok := err.(auth.ErrQueryFailed); ok {
				c.AbortWithError(http.StatusBadGateway, err)
				return
			}
		}
		log.Info(details)
		c.JSON(http.StatusOK, details)
		return
	} else if c.Request.Method == "DELETE" {
		if err := ua.RemoveAccount(email); err != nil {
			c.AbortWithError(http.StatusBadGateway, err)
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
		if err := ua.UpdateAccDetails(newDetails); err != nil {
			if _, ok := err.(auth.ErrNotFound); ok {
				c.AbortWithError(http.StatusBadRequest, err)
				return
			} else if _, ok := err.(auth.ErrQueryFailed); ok {
				c.AbortWithError(http.StatusBadGateway, err)
				return
			} else {
				c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Unknown error on the server"))
				return
			}
		}
		c.AbortWithStatus(http.StatusOK)
		return
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
			c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed database collection connection"))
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

	log.Fatal(r.Run(":8080"))
}
