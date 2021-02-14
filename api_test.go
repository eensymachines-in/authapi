package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

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
	body, _ := json.Marshal(creds)
	resp, err := http.Post(fmt.Sprintf("http://localhost:8080/authenticate/%s", creds["email"]), "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexepcted error when posting a new user account")
	assert.NotNil(t, resp, "Unexpected nil response from server for posting a new account")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting a 200 ok on posting new user account")
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
func insertUser(email, passwd, name, loc, phone string, role int, t *testing.T, expected int) {
	url := "http://localhost:8080/users"
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
	url := "http://localhost:8080/users"
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
}

func delUser(email, authTok string, t *testing.T, expected int) {
	url := "http://localhost:8080/users"
	client := &http.Client{}
	req, _ := http.NewRequest("DELETE", fmt.Sprintf("%s/%s", url, email), nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", authTok))
	resp, err := client.Do(req)
	assert.Nil(t, err, "Unexpected error making a delete request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting 200 response status code")
}

func patchUser(email, passwd, auth string, t *testing.T, expected int) {
	url := "http://localhost:8080/users"
	ua := map[string]interface{}{
		"email":  email,
		"passwd": passwd,
	}
	body, _ := json.Marshal(ua)
	req, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/%s", url, ua["email"]), bytes.NewBuffer(body))
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error making a patch request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, expected, resp.StatusCode, "Was expecting 200 response status code")
}

func authorizeUser(auth string, t *testing.T, expected int) {
	req, _ := http.NewRequest("GET", "http://localhost:8080/authorize", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	resp, err := (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexepcted error when authorizing the user account")
	assert.NotNil(t, resp, "Unexpected nil response from server authorizing an account")
	assert.Equal(t, expected, resp.StatusCode, "Unexpected response when authorizing the user")
}

func refreshUser(refr string, t *testing.T, expected int) map[string]string {
	req, _ := http.NewRequest("GET", "http://localhost:8080/authorize?refresh=true", nil)
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
	req, _ := http.NewRequest("DELETE", "http://localhost:8080/authorize", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
	(&http.Client{}).Do(req)
	req, _ = http.NewRequest("DELETE", "http://localhost:8080/authorize?refresh=true", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", refr))
	(&http.Client{}).Do(req)
}

func TestUser(t *testing.T) {
	// Insert a legit user
	insertUser("kneerun@someshitdomain.com", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 200)
	toks := authenticateUser("kneerun@someshitdomain.com", "unjun@41993", t, 200)
	t.Log(toks)
	// Wrong authentication
	authenticateUser("kneerun@someshitdomain.com", "@41993", t, 401)
	authenticateUser("bababocha@someshitdomain.com", "unjun@41993", t, 400)

	// +++++++++++++++
	insertUser("", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun@", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun@shitdomain", "unjun@41993", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	// ++++++++++++
	insertUser("kneerun@someshitdomain.com", "", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun@someshitdomain.com", "unjun@41993fdfsdfsdfsdfdsfdsfdsfsdfdswrewr", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)
	insertUser("kneerun@someshitdomain.com", "12345678", "Niranjan Awati", "Pune, 411057", "+91 673443 4353", 2, t, 400)

	// ++++++++++++
	// putting new user details
	putUser("kneerun@someshitdomain.com", "NewShitName", "Pune, 411038", "53435435345 3534", toks["auth"], t, 200)
	putUser("kneerun@someshitdomain.com", "", "", "", toks["auth"], t, 400)

	// ++++++++++++++
	// patching the use for the password
	patchUser("kneerun@someshitdomain.com", "unjun@41993#@", toks["auth"], t, 200)
	toks = authenticateUser("kneerun@someshitdomain.com", "unjun@41993#@", t, 200)
	authorizeUser(toks["auth"], t, 200)
	// Here we try to remove the user with requisite authentication
	delUser("kneerun@someshitdomain.com", toks["auth"], t, 200)
	// since below we are using the token from kneerun@someshitdomain.com and trying to delete modafucka@someshitdomain.com this will forbid the request
	// and rightly so
	delUser("modafucka@someshitdomain.com", toks["auth"], t, 403) //trying to delete an user that's not registered
	<-time.After(72 * time.Second)

	authorizeUser(toks["auth"], t, 401)
	// +++++++++++ time to see if we can refresh the tokens
	toks = refreshUser(toks["refr"], t, 200) // here the original refresh token shall be orphaned
	t.Log(toks)
	logoutUser(toks["auth"], toks["refr"], t)
}
