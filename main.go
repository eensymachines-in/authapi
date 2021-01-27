package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/eensymachines-in/auth"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2"
)

// handlDevices : handler for the route /devices
func handlDevices(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	devregColl, _ := c.Get("devreg")
	blcklColl, _ := c.Get("devblacklist")
	serial := c.Param("serial")
	if c.Request.Method == "GET" {
		// this is when we are trying to get the device registration of a specific device
		status, err := devregColl.(*auth.DeviceRegColl).DeviceOfSerial(serial)
		if err != nil {
			// Failed query to get the device by the serial
			log.Errorf("Failed DeviceOfSerial, could not get device of serial: %s", err)
			c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to get device with serial %s", serial))
			return
		}
		if *status == (auth.DeviceStatus{}) {
			// which means the serial number wasnt found as we have an empty result
			log.Errorf("No deice with serial: %s found registered", serial)
			c.AbortWithError(http.StatusNotFound, fmt.Errorf("No deice with serial: %s found registered", serial))
			return
		}
		c.JSON(http.StatusOK, status) // we have the device status, we are 200OK here
		return
	} else if c.Request.Method == "PATCH" {
		// modification to device status
		lock := c.Query("lock")
		black := c.Query("black")
		if lock != "" {
			value, err := strconv.ParseBool(lock) // lock param is to be a boolean
			if err != nil {
				log.Errorf("Lock status is invalid, expecting a bool value, got :%v", lock)
				c.AbortWithError(http.StatusBadRequest, fmt.Errorf("check lock status, in the query params"))
				return
			}
			if value {
				if err := devregColl.(*auth.DeviceRegColl).LockDevice(serial); err != nil {
					log.Errorf("Failed to lock device :%s", err)
					c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to lock device, one or more operations on the server failed"))
					return
				}
			} else {
				if err := devregColl.(*auth.DeviceRegColl).UnLockDevice(serial); err != nil {
					log.Errorf("Failed to unlock device :%s", err)
					c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to unlock device, one or more operations on the server failed"))
					return
				}
			}
		}
		if black != "" {
			// when the device needs to be blacklisted or whitelisted
			value, err := strconv.ParseBool(black) //since the qparam is to be a boolean
			if err != nil {
				log.Errorf("Black status is invalid, expecting a bool value, got :%v", black)
				c.AbortWithError(http.StatusBadRequest, fmt.Errorf("check black status, in the query params"))
				return
			}
			if value {
				// device needs to be black listed
				if err := blcklColl.(*auth.BlacklistColl).Black(&auth.Blacklist{Serial: serial, Reason: "Test change in the blacklist"}); err != nil {
					log.Errorf("Failed to blacklist device :%s", err)
					c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to lock device, one or more operations on the server failed"))
					return
				}
			} else {
				// the device needs to be whitelisted
				if err := blcklColl.(*auth.BlacklistColl).White(serial); err != nil {
					log.Errorf("Failed to unblock device :%s", err)
					c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("Failed to unblack device, one or more operations on the server failed"))
					return
				}
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
	devices := r.Group("/devices")
	devices.Use(lclDbConnect())
	devices.GET("/:serial", handlDevices)
	devices.PATCH("/:serial", handlDevices)
	log.Fatal(r.Run(":8080"))
}
