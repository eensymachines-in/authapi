package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	b64 "encoding/base64"

	"github.com/eensymachines-in/auth/v2"
	"github.com/stretchr/testify/assert"
)

const (
	testServer string = "http://localhost"
)

func readResponseBody(resp *http.Response, t *testing.T) map[string]interface{} {
	defer resp.Body.Close()
	target := map[string]interface{}{}
	if json.NewDecoder(resp.Body).Decode(&target) != nil {
		// t.Error("Failed to decode the authentication response containing tokenss")
		return nil
	}
	return target
}

// ++++++++++++++++++++++++++++
// Helper functions for testing
// ++++++++++++++++++++++++++++
func authenticateUser(email, passwd string, t *testing.T, expected int) map[string]string {
	// +++++++++++++++++++
	// authenticating the user now with correct password
	creds := map[string]interface{}{
		"email":  email,
		"passwd": passwd,
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/authenticate/%s", testServer, creds["email"]), nil)
	encoded := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", creds["email"], creds["passwd"])))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encoded))
	resp, err := (&http.Client{}).Do(req)
	// ++++++++++ assertions
	assert.Nil(t, err, "Unexepcted error when posting a new user account")
	assert.NotNil(t, resp, "Unexpected nil response from server for posting a new account")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting a 200 ok on posting new user account")
	// ++++++++++ when the authentication is complete
	if expected == 200 {
		// Only when authentication is a success
		data := readResponseBody(resp, t)
		t.Logf("Authentication token %s", data["auth"])
		t.Logf("Refresh token %s", data["refr"])
		return map[string]string{"auth": fmt.Sprintf("%s", data["auth"]), "refr": fmt.Sprintf("%s", data["refr"])}
	}
	return nil
}
func insertUser(email, passwd, name, loc, phone string, role int, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/users", testServer)
	ua := map[string]interface{}{
		"email":  email,
		"role":   role,
		"passwd": passwd,
		"name":   name,
		"phone":  phone,
		"loc":    loc,
	}
	body, _ := json.Marshal(ua)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexepcted error when posting a new user account")
	assert.NotNil(t, resp, "Unexpected nil response from server for posting a new account")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting a 200 ok on posting new user account")
}
func putUser(email, name, loc, phone, auth string, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/users", testServer)
	ua := map[string]interface{}{
		"email": email,
		"name":  name,
		"phone": phone,
		"loc":   loc,
	}
	body, _ := json.Marshal(ua)
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/%s", url, ua["email"]), bytes.NewBuffer(body))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error making a put request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, expected, resp.StatusCode, "Incorrect response status code")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}
}

func delUser(email, authTok string, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/users", testServer)
	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/%s", url, email), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authTok))
	resp, err := client.Do(req)
	assert.Nil(t, err, "Unexpected error making a delete request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting 200 response status code")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}
}

func patchUser(email, passwd string, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/users", testServer)
	// +++++++++++ making a new request, imind you since this is about changing the password it'd be base 64 encoded
	req, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/%s", url, email), nil)
	encoded := b64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", email, passwd)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", encoded))
	resp, err := (&http.Client{}).Do(req)

	assert.Nil(t, err, "Unexpected error making a patch request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting 200 response status code")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}
}

func authorizeUser(auth string, t *testing.T, role, expected int) {
	var req *http.Request
	if role == 0 {
		req, _ = http.NewRequest("GET", fmt.Sprintf("%s/authorize", testServer), nil)
	} else {
		req, _ = http.NewRequest("GET", fmt.Sprintf("%s/authorize?lvl=%d", testServer, role), nil)
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexepcted error when authorizing the user account")
	assert.NotNil(t, resp, "Unexpected nil response from server authorizing an account")
	assert.Equal(t, expected, resp.StatusCode, "Unexpected response when authorizing the user")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}
}

func refreshUser(refr string, t *testing.T, expected int) map[string]string {
	req, _ := http.NewRequest("GET", fmt.Sprintf("%s/authorize?refresh=true", testServer), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", refr))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexepcted error when authorizing the user account")
	assert.NotNil(t, resp, "Unexpected nil response from server authorizing an account")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting a 401 ok authorizing an account")
	if expected == 200 {
		// Only if it is expected to be a 200 ok authentication
		defer resp.Body.Close()
		target := map[string]string{}
		if json.NewDecoder(resp.Body).Decode(&target) != nil {
			t.Error("Failed to decode the authentication response containing tokenss")
		}
		t.Logf("Authentication token %s", target["auth"])
		t.Logf("Refresh token %s", target["refr"])
		return target
	}
	return nil

}
func logoutUser(auth, refr string, t *testing.T) {
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/authorize", testServer), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	(&http.Client{}).Do(req)
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/authorize?refresh=true", testServer), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", refr))
	(&http.Client{}).Do(req)
}
func insertDeviceReg(reg *auth.DeviceReg, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/devices", testServer)
	body, _ := json.Marshal(reg)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))

	assert.Nil(t, err, "Unexepcted error when posting a new user account")
	assert.NotNil(t, resp, "Unexpected nil response from server for posting a new account")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting a 200 ok on posting new user account")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}

}
func delDeviceReg(serial, auth string, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/devices/%s", testServer, serial)
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error in Do-ing the request, failed http request")
	assert.Equal(t, expected, resp.StatusCode, "Unexpected response code when delDeviceReg")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	} else {
		t.Log(readResponseBody(resp, t))
	}

}
func getDeviceReg(serial string, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/devices/%s", testServer, serial)
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error in Do-ing the request, failed http request")
	assert.Equal(t, expected, resp.StatusCode, "Unexpected response code when delDeviceReg")
	if expected == 200 {
		// Only if it is expected to be a 200 ok authentication
		defer resp.Body.Close()
		target := &auth.DeviceReg{}
		if json.NewDecoder(resp.Body).Decode(&target) != nil {
			t.Error("Failed to decode the authentication response containing tokenss")
		}
		t.Log(target)
		return
	} else {
		t.Log(readResponseBody(resp, t))
	}
}
func lockDeviceReg(serial, auth string, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/devices/%s?lock=true", testServer, serial)
	req, _ := http.NewRequest("PATCH", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error in Do-ing the request, failed http request")
	assert.Equal(t, expected, resp.StatusCode, "Unexpected response code when delDeviceReg")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}
}
func unlockDeviceReg(serial, auth string, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/devices/%s?lock=false", testServer, serial)
	req, _ := http.NewRequest("PATCH", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error in Do-ing the request, failed http request")
	assert.Equal(t, expected, resp.StatusCode, "Unexpected response code when delDeviceReg")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}
}
func blackUnblack(serial, auth string, black bool, t *testing.T, expected int) {
	url := fmt.Sprintf("%s/devices/%s?black=%t", testServer, serial, black)
	req, _ := http.NewRequest("PATCH", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error in Do-ing the request, failed http request")
	assert.Equal(t, expected, resp.StatusCode, "Unexpected response code when delDeviceReg")
	if expected != 200 {
		t.Log(readResponseBody(resp, t))
	}
}

// Lets test all the bad passwords for the user accounts
func TBadUserInsert(t *testing.T) {
	// +++++++++++++++ bad password combinations
	insertUser("testuser@someshitdomain.com", "", "Niranjan Awati", "Pune, 411057", "+916734434353", 2, t, 400)
	insertUser("testuser@someshitdomain.com", "dsfsdf", "Niranjan Awati", "Pune, 411057", "+916734434353", 2, t, 400)
	insertUser("testuser@someshitdomain.com", "dsfsdfdsfsdfdsfsdfdsfsdf", "Niranjan Awati", "Pune, 411057", "+916734434353", 2, t, 400)
	// ++++++++++++ Now with invalid email addresses
	insertUser("", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun@", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun@shitdomain", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)

	// +++++++++++++ now with the wrong phone number
	insertUser("kissmyarse@someshitdomain.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "", 2, t, 400)
	insertUser("kissmyarse@someshitdomain.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "sdfsfsdf", 2, t, 400)
	insertUser("kissmyarse@someshitdomain.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+915345sdfsfsdf", 2, t, 400)
}

func TWrongAuth(t *testing.T) {
	// Wrong authentication
	authenticateUser("kneerun@someshitdomain.com", "@41993", t, 401)
	authenticateUser("bababocha@someshitdomain.com", "unjun@41993", t, 404)
	authenticateUser("kneerun@someshitdomain.com", "", t, 401)
}

func TPutBadUser(t *testing.T, authtok string) {
	putUser("kneerun@someshitdomain.com", "", "", "", authtok, t, 400)
	putUser("kneerun@someshitdomain.com", "nigga fat arse", "", "", authtok, t, 400)
	putUser("kneerun@someshitdomain.com", "nigga fat arse", "your momas big fat arse", "", authtok, t, 400)
	putUser("kneerun@someshitdomain.com", "nigga fat arse", "your momas big fat arse", "", authtok, t, 400)
	putUser("kneerun@someshitdomain.com", "nigga fat arse", "your momas big fat arse", "+91fdsffdjj", authtok, t, 400)
	putUser("kneerun@someshitdomain.com", "nigga fat arse", "your momas big fat arse", "+91fdsffdjj5345", authtok, t, 400)
	// Since the email and the token would not match - this is flagged as unauthorized
	putUser("randomguy@someshitdomain.com", "nigga fat arse", "", "", authtok, t, 401)
}

func TPatchBadPasswd(t *testing.T) {
	patchUser("kneerun@someshitdomain.com", "", t, 401)
}

func TestEnlistingAccs(t *testing.T) {
	insertUser("kneerun@someshitdomain.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+916734434353", 2, t, 200)
	toks := authenticateUser("kneerun@someshitdomain.com", "unjun@41993", t, 200)

	url := fmt.Sprintf("%s/users", testServer)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", toks["auth"]))
	resp, err := (&http.Client{}).Do(req)
	// happy requst, this should sail thru - till ofcourse you clear the database
	assert.Nil(t, err, "Unexpected error in Do-ing the request, failed http request")
	assert.Equal(t, 200, resp.StatusCode, "Unexpected response code when TestEnlistingAccs")
	if resp.StatusCode == 200 {
		defer resp.Body.Close()
		target := []map[string]interface{}{}
		if json.NewDecoder(resp.Body).Decode(&target) != nil {
			panic("Error reading the accounts enlisting")
		}
		t.Log(target)
	}
	// now we send in the request without any authorization
	req, _ = http.NewRequest("GET", url, nil)
	resp, err = (&http.Client{}).Do(req)
	resp, err = (&http.Client{}).Do(req)
	// expected response code is 401, since this req requires the user to have admin privileges
	assert.Equal(t, 400, resp.StatusCode, "Unexpected response code when TestEnlistingAccs")
	<-time.After(72 * time.Second)
	// Now the authentication token should have expired
	req, _ = http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", toks["auth"]))
	resp, err = (&http.Client{}).Do(req)
	assert.Equal(t, 401, resp.StatusCode, "Unexpected response code when TestEnlistingAccs")
	// Here we try to add an user with lower privileges
	insertUser("kneerun@modafucka.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+916734434353", 1, t, 200)
	toks = authenticateUser("kneerun@modafucka.com", "unjun@41993", t, 200)
	req, _ = http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", toks["auth"]))
	resp, err = (&http.Client{}).Do(req)
	assert.Equal(t, 403, resp.StatusCode, "Unexpected response code when TestEnlistingAccs")
	/*CLEAR THE DATABASE*/
}

func TestDeleteAccs(t *testing.T) {
	insertUser("kneerun@someshitdomain.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+916734434353", 2, t, 200)
	toks := authenticateUser("kneerun@someshitdomain.com", "unjun@41993", t, 200)
	insertUser("kneerun@modafucka.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+916734434353", 1, t, 200)

	url := fmt.Sprintf("%s/users/%s", testServer, "kneerun@modafucka.com")
	req, _ := http.NewRequest("DELETE", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", toks["auth"]))
	resp, _ := (&http.Client{}).Do(req)
	assert.Equal(t, 200, resp.StatusCode, "Unexpected response code when TestDeleteAccs")

	url = fmt.Sprintf("%s/users/%s", testServer, "kneerun@someshitdomain.com")
	req, _ = http.NewRequest("DELETE", url, nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", toks["auth"]))
	resp, _ = (&http.Client{}).Do(req)
	assert.Equal(t, 403, resp.StatusCode, "Unexpected response code when TestDeleteAccs")
}

func adminToks(t *testing.T) map[string]string {
	return authenticateUser("kneerunjun@gmail.com", "106456!41993", t, 200)
}

func TestUserAccountsOnly(t *testing.T) {
	// Insert a legit user
	insertUser("kneerun@someshitdomain.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+916734434353", 1, t, 200)
	thissUserToks := authenticateUser("kneerun@someshitdomain.com", "unjun@41993", t, 200)
	TWrongAuth(t)
	TBadUserInsert(t)
	// ++++++++++++
	// putting new user details
	putUser("kneerun@someshitdomain.com", "NewShitName", "Pune, 411038", "+91534589885435", thissUserToks["auth"], t, 200)
	TPutBadUser(t, thissUserToks["auth"])

	// // ++++++++++++++
	// // patching the use for the password
	patchUser("kneerun@someshitdomain.com", "unjun@41993!@", t, 200)
	TPatchBadPasswd(t)
	thissUserToks = authenticateUser("kneerun@someshitdomain.com", "unjun@41993!@", t, 200)

	authorizeUser(thissUserToks["auth"], t, 1, 200) // the user is already at level 2
	authorizeUser(thissUserToks["auth"], t, 2, 403)
	authorizeUser(thissUserToks["auth"], t, 3, 403) // when the user is not elevated enough

	// Here we try to remove the user with requisite authentication
	// We need admin authrization to delete any user
	adminAuth := adminToks(t)
	delUser("kneerun@someshitdomain.com", adminAuth["auth"], t, 200)
	// // // since below we are using the token from kneerun@someshitdomain.com and trying to delete modafucka@someshitdomain.com this will forbid the request
	// // // and rightly so
	delUser("modafucka@someshitdomain.com", adminAuth["auth"], t, 404) //trying to delete an user that's not registered
	<-time.After(72 * time.Second)

	authorizeUser(thissUserToks["auth"], t, 1, 401)
	// +++++++++++ time to see if we can refresh the tokens
	thissUserToks = refreshUser(thissUserToks["refr"], t, 200) // here the original refresh token shall be orphaned
	t.Log("Tokens refreshed ..............")
	t.Log(thissUserToks)
	logoutUser(thissUserToks["auth"], thissUserToks["refr"], t)
	// There's one more when the token is expired, logout will emit 401
}

var reg = &auth.DeviceReg{
	User:     "kneerun@someshit.com",
	Hardware: "BCM2835, SoC Qualcomm",
	Serial:   "b83ad4e3-60b2-4fbe-b46d",
	Model:    "RaspberryPi 3B",
}

func TestBadDeviceRegInsert(t *testing.T) {
	// ++++++++++++++ THIS WILL NOT WORK +++++++++++++
	// since the user is not registered, the device cannot be registered
	insertDeviceReg(reg, t, 400) // duplicate device insertion
	newReg := &auth.DeviceReg{
		User:     "",
		Hardware: "BCM2835, SoC Qualcomm",
		Serial:   "b83ad4e3-60b2-4fbe-b46d",
		Model:    "RaspberryPi 3B",
	} // the one in which the user email id is missing
	insertDeviceReg(newReg, t, 404)
	newReg = &auth.DeviceReg{
		User:     "kneerun@someshit.com",
		Hardware: "BCM2835, SoC Qualcomm",
		Serial:   "",
		Model:    "RaspberryPi 3B",
	} //the one in which the serial number is missing
	insertDeviceReg(newReg, t, 400)
	newReg = &auth.DeviceReg{
		User:     "kneerun@", // unregistered account
		Hardware: "BCM2835, SoC Qualcomm",
		Serial:   "b83ad4e3-60b2-4fbe-b46ff",
		Model:    "RaspberryPi 3B",
	} //the one in which the serial number is missing
	insertDeviceReg(newReg, t, 404)
}
func TestUserDevices(t *testing.T) {
	insertUser(reg.User, "somepass@34355", "Cock block", "In da hood", "+915534554", 2, t, 200)
	authenticateUser(reg.User, "somepass@34355", t, 200)
	insertDeviceReg(reg, t, 200)
	url := fmt.Sprintf("%s/users/%s/devices", testServer, reg.User)
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error in Do-ing the request, failed http request")
	assert.Equal(t, 200, resp.StatusCode, "Unexpected response code when delDeviceReg")
	defer resp.Body.Close()
	target := []interface{}{}
	if json.NewDecoder(resp.Body).Decode(&target) != nil {
		// t.Error("Failed to decode the authentication response containing tokenss")
		panic("TestUserDevices:Failed to unmarshall response body")
	}
	t.Log(target)
}
func TestDevices(t *testing.T) {
	insertUser(reg.User, "somepass@34355", "Cock block", "In da hood", "+915534554", 2, t, 200)
	toks := authenticateUser(reg.User, "somepass@34355", t, 200)
	insertDeviceReg(reg, t, 200)
	TestBadDeviceRegInsert(t)

	getDeviceReg(reg.Serial, t, 200)
	getDeviceReg("dd03f4a2-5962-434c", t, 404)

	lockDeviceReg(reg.Serial, toks["auth"], t, 200)
	lockDeviceReg("dd03f4a2-5962-434c", toks["auth"], t, 404)

	unlockDeviceReg(reg.Serial, toks["auth"], t, 200)
	unlockDeviceReg("dd03f4a2-5962-434c", toks["auth"], t, 404)

	delDeviceReg(reg.Serial, toks["auth"], t, 200)
	delDeviceReg("dd03f4a2-5962-434c", toks["auth"], t, 404)

	delUser(reg.User, toks["auth"], t, 403)
}

// TestUsrAccToDevices: this shall test all the user account to devices relation
// When an account is deleted, the devices owned by the account are stripped off their registration and blacklisted
// if the same device has to be re-deployed it has to be explicitly white listed by an admin
func TestUsrAccToDevices(t *testing.T) {
	insertUser(reg.User, "somepass@34355", "Cock block", "In da hood", "+915534554", 1, t, 200)
	toks := authenticateUser("kneerunjun@gmail.com", "106456!41993", t, 200)
	insertDeviceReg(reg, t, 200)
	lockDeviceReg(reg.Serial, toks["auth"], t, 200)
	unlockDeviceReg(reg.Serial, toks["auth"], t, 200)

	delUser(reg.User, toks["auth"], t, 200)
	// Now that the user account has been removed, the device would be blacklisted
	// lets try to enlist the blacklisted devices

	url := fmt.Sprintf("%s/devices?black=true", testServer)
	req, _ := http.NewRequest("GET", url, nil)
	resp, _ := (&http.Client{}).Do(req)
	assert.Equal(t, 200, resp.StatusCode, "Unexpected response code when enlisting the blacked devices")
	if resp.StatusCode == 200 {
		// Only if it is expected to be a 200 ok authentication
		defer resp.Body.Close()
		target := []auth.Blacklist{}
		if json.NewDecoder(resp.Body).Decode(&target) != nil {
			t.Error("Failed to decode the authentication response containing tokenss")
		}
		t.Log("below are the black listed devices ...")
		t.Log(target)
		return
	}
	insertDeviceReg(reg, t, 404)                                                                // user account is not found, hence would be rejected
	insertUser(reg.User, "somepass@34355", "Cock block", "In da hood", "+915534554", 1, t, 200) // so we try to register the account again
	// toks = authenticateUser(reg.User, "somepass@34355", t, 200)
	// // but then the device is still blacklisted
	// // so we then unblack the device
	insertDeviceReg(reg, t, 403) // before unblacking the device inserting the device again is not possible
	blackUnblack(reg.Serial, toks["auth"], false, t, 200)
	insertDeviceReg(reg, t, 200) // same device registration now can be pushed
	// // and then again everything is deleted
	delUser(reg.User, toks["auth"], t, 200)
}
