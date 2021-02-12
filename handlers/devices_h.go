package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/eensymachines-in/auth"
	ex "github.com/eensymachines-in/errx"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

// HandlDevices : handler for the route /devices
func HandlDevices(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	devregColl, _ := c.Get("devreg")
	blcklColl, _ := c.Get("devblacklist")
	serial := c.Param("serial")
	if c.Request.Method == "GET" {
		// this is when we are trying to get the device registration of a specific device
		status, err := devregColl.(*auth.DeviceRegColl).DeviceOfSerial(serial)
		if ex.DigestErr(err, c) != 0 {
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
			if ex.DigestErr(err, c) != 0 {
				return
			}
			if value {
				if ex.DigestErr(devregColl.(*auth.DeviceRegColl).LockDevice(serial), c) != 0 {
					return
				}
			} else {
				if ex.DigestErr(devregColl.(*auth.DeviceRegColl).UnLockDevice(serial), c) != 0 {
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
				if ex.DigestErr(blcklColl.(*auth.BlacklistColl).Black(&auth.Blacklist{Serial: serial, Reason: "Test change in the blacklist"}), c) != 0 {
					return
				}
			} else {
				// the device needs to be whitelisted
				if ex.DigestErr(blcklColl.(*auth.BlacklistColl).White(serial), c) != 0 {
					return
				}
			}
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "POST" {
		devReg := &auth.DeviceReg{}
		if err := c.ShouldBindJSON(devReg); err != nil {
			log.Errorf("handlDevices: Failed to bind device registration from request body %s", err)
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Failed to read device registration details, kindly check and send again"))
			return
		}
		if ex.DigestErr(devregColl.(*auth.DeviceRegColl).InsertDeviceReg(devReg, blcklColl.(*auth.BlacklistColl).Collection), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	}

}
