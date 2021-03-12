package handlers

import (
	"fmt"
	"net/http"
	"strconv"

	auth "github.com/eensymachines-in/auth/v2"
	ex "github.com/eensymachines-in/errx"
	"github.com/gin-gonic/gin"
)

// HandlDevice : handles all the requests pertaining to a single device
func HandlDevice(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	val, _ := c.Get("devreg")
	devregColl := val.(*auth.DeviceRegColl)
	val, _ = c.Get("devblacklist")
	blcklColl := val.(*auth.BlacklistColl)
	serial := c.Param("serial")
	if c.Request.Method == "GET" {
		// this is when we are trying to get the device registration of a specific device
		status, err := devregColl.DeviceOfSerial(serial)
		if ex.DigestErr(err, c) != 0 {
			return
		}
		if *status == (auth.DeviceStatus{}) {
			ex.DigestErr(ex.NewErr(&ex.ErrNotFound{}, fmt.Errorf("No deice with serial: %s found registered", serial), fmt.Sprintf("Failed to get device of serial %s", serial), "HandlDevices/empty devices"), c)
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
				if ex.DigestErr(devregColl.LockDevice(serial), c) != 0 {
					return
				}
			} else {
				if ex.DigestErr(devregColl.UnLockDevice(serial), c) != 0 {
					return
				}
			}
		}
		if black != "" {
			// when the device needs to be blacklisted or whitelisted
			value, err := strconv.ParseBool(black) //since the qparam is to be a boolean
			if err != nil {
				ex.DigestErr(ex.NewErr(&ex.ErrInvalid{}, fmt.Errorf("Patching device: /devices/:serial?black=true is the correct format"), fmt.Sprintf("Black status is invalid, expecting a bool value, got :%v", black), "HandlDevices/PATCH"), c)
				return
			}
			if value {
				// device needs to be black listed
				// Even before the device is black listed it has to be removed from the registration
				if ex.DigestErr(devregColl.RemoveDeviceReg(serial), c) != 0 {
					return
				}
				if ex.DigestErr(blcklColl.Black(&auth.Blacklist{Serial: serial, Reason: "Test change in the blacklist"}), c) != 0 {
					return
				}
			} else {
				// the device needs to be whitelisted
				if ex.DigestErr(blcklColl.White(serial), c) != 0 {
					return
				}
			}
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "DELETE" {
		if ex.DigestErr(devregColl.RemoveDeviceReg(serial), c) != 0 {
			return
		}
	}
}

// HandlDevices : handler for the route /devices
func HandlDevices(c *gin.Context) {
	closeSession, _ := c.Get("close_session")
	defer closeSession.(func())() // this closes the db session when done
	val, _ := c.Get("devreg")
	devregColl := val.(*auth.DeviceRegColl)
	val, _ = c.Get("devblacklist")
	blcklColl := val.(*auth.BlacklistColl)
	// serial := c.Param("serial")
	if c.Request.Method == "POST" {
		devReg := &auth.DeviceReg{}
		if err := c.ShouldBindJSON(devReg); err != nil {
			ex.DigestErr(ex.NewErr(&ex.ErrJSONBind{}, fmt.Errorf("handlDevices: Failed to bind device registration from request body %s", err), fmt.Sprintf("Failed to read device registration details, kindly check and send again"), "HandlDevices/PATCH"), c)
			return
		}
		// Before we go ahead to register the device, the owner account has to be registered
		col, _ := c.Get("userreg")
		userReg := col.(*auth.UserAccounts)
		if !userReg.IsRegistered(devReg.User) {
			// If the account isnt registered, the device cannot be registered
			ex.DigestErr(ex.NewErr(&ex.ErrNotFound{}, fmt.Errorf("Unable to find the user account registered, %s", devReg.User), "User account isnt registered, cannot register device", "POST/devices"), c)
			return
		}
		// Once we have it confirmed that owner account is registered, we can move ahead to insert the device registration
		if ex.DigestErr(devregColl.InsertDeviceReg(devReg, blcklColl.Collection), c) != 0 {
			return
		}
		c.AbortWithStatus(http.StatusOK)
		return
	} else if c.Request.Method == "GET" {
		if c.Query("black") != "" {
			// when the client code is requesting all the blacklisted devices
			blacked := []auth.Blacklist{}
			if ex.DigestErr(blcklColl.Enlist(&blacked), c) != 0 {
				return
			}
			c.JSON(http.StatusOK, blacked)
			return
		}
	}
}
