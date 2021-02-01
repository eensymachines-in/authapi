package main

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/eensymachines-in/auth"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
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
			c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed to get device with serial %s", serial))
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
					if _, ok := err.(auth.ErrQueryFailed); ok {
						c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed to lock device, one or more operations on the server failed"))
					} else if _, ok := err.(auth.ErrInvalid); ok {
						c.AbortWithError(http.StatusBadRequest, err)
					}
					return
				}
			} else {
				if err := devregColl.(*auth.DeviceRegColl).UnLockDevice(serial); err != nil {
					log.Errorf("Failed to unlock device :%s", err)
					if _, ok := err.(auth.ErrQueryFailed); ok {
						c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed to unlock device, one or more operations on the server failed"))
					} else if _, ok := err.(auth.ErrInvalid); ok {
						c.AbortWithError(http.StatusBadRequest, err)
					}
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
					c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed to lock device, one or more operations on the server failed"))
					return
				}
			} else {
				// the device needs to be whitelisted
				if err := blcklColl.(*auth.BlacklistColl).White(serial); err != nil {
					log.Errorf("Failed to unblock device :%s", err)
					c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Failed to unblack device, one or more operations on the server failed"))
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
		err := devregColl.(*auth.DeviceRegColl).InsertDeviceReg(devReg, blcklColl.(*auth.BlacklistColl).Collection)
		if _, ok := err.(auth.ErrInvalid); ok {
			log.Errorf("handlDevices: Failed to insert device registration %s", err)
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Invalid device registration details, kindly check and send again"))
			return
		} else if _, ok := err.(auth.ErrForbid); ok {
			log.Errorf("handlDevices: Failed to insert device registration %s", err)
			c.AbortWithError(http.StatusForbidden, fmt.Errorf("Device %s cannot be registered, it maybe black listed. Please contact administrator", devReg.Serial))
			return
		} else if _, ok := err.(auth.ErrDuplicate); ok {
			log.Errorf("handlDevices: Failed to insert device registration %s", err)
			c.AbortWithError(http.StatusBadRequest, fmt.Errorf("Device %s is already registered, cannot have 2 devices with the same serial registered again", devReg.Serial))
			return
		} else if _, ok := err.(auth.ErrQueryFailed); ok {
			log.Errorf("handlDevices: Failed to insert device registration %s", err)
			c.AbortWithError(http.StatusBadGateway, fmt.Errorf("Server operation failed while registering this device, please try again in sometime. If the problem persists you may have to contact an administrator"))
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	}

}
