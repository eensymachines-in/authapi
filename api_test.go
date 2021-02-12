package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuthentication(t *testing.T) {
	// +++++++++++
	// Creating a new user so as to authenticate
	// +++++++++++
	url := "http://localhost:8080/users"
	ua := map[string]interface{}{
		"email":  "kneeru@someshit.com",
		"role":   2,
		"passwd": "ranjan_wati!538",
		"name":   "Niranjan Awati",
		"phone":  "+91 5453500 5435345",
		"loc":    "Pune, 411057",
	}
	body, _ := json.Marshal(ua)
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexepcted error when posting a new user account")
	assert.NotNil(t, resp, "Unexpected nil response from server for posting a new account")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting a 200 ok on posting new user account")

	// +++++++++++++++++++
	// authenticating the user now with correct password
	creds := map[string]interface{}{
		"email":  "kneeru@someshit.com",
		"passwd": "ranjan_wati!538",
	}
	body, _ = json.Marshal(ua)
	resp, err = http.Post(fmt.Sprintf("http://localhost:8080/authenticate/%s", creds["email"]), "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexepcted error when posting a new user account")
	assert.NotNil(t, resp, "Unexpected nil response from server for posting a new account")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting a 200 ok on posting new user account")

	defer resp.Body.Close()
	target := map[string]string{}
	if json.NewDecoder(resp.Body).Decode(&target) != nil {
		t.Error("Failed to decode the authentication response containing tokenss")
	}
	t.Logf("Authentication token %s", target["auth"])
	t.Logf("Refresh token %s", target["refr"])

	// ++++++++++
	// now lets see if we can authorize using the tokens we have just received
	req, _ := http.NewRequest("GET", "http://localhost:8080/authorize", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", target["auth"]))
	client := &http.Client{}
	resp, err = client.Do(req)
	assert.Nil(t, err, "Unexepcted error when authorizing the user account")
	assert.NotNil(t, resp, "Unexpected nil response from server authorizing an account")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting a 200 ok authorizing an account")

	// ++++++++++++++ trying to authorize after 70 seconds - thats the time it needs for auth token to expire
	t.Log("Now waiting for the token to auto expire from the cache")
	<-time.After(71 * time.Second)
	req, _ = http.NewRequest("GET", "http://localhost:8080/authorize", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", target["auth"]))
	resp, err = client.Do(req)
	assert.Nil(t, err, "Unexepcted error when authorizing the user account")
	assert.NotNil(t, resp, "Unexpected nil response from server authorizing an account")
	assert.Equal(t, 401, resp.StatusCode, "Was expecting a 401 ok authorizing an account")
	// +++++++++++++++++
	// Now refreshing the token set
	req, _ = http.NewRequest("GET", "http://localhost:8080/authorize?refresh=true", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", target["refr"]))
	resp, err = client.Do(req)
	assert.Nil(t, err, "Unexepcted error when refreshing the user account")
	assert.NotNil(t, resp, "Unexpected nil response from server refreshing an account")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting a 200 ok refreshing an account")
	defer resp.Body.Close()
	target = map[string]string{}
	if json.NewDecoder(resp.Body).Decode(&target) != nil {
		t.Error("Failed to decode the authentication response containing tokenss")
	}
	// then logging out the user from the auth cache
	req, _ = http.NewRequest("DELETE", "http://localhost:8080/authorize", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", target["auth"]))
	client.Do(req)
	req, _ = http.NewRequest("DELETE", "http://localhost:8080/authorize?refresh=true", nil)
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", target["refr"]))
	client.Do(req)
	// +++++++++++++
	// now deleting the account we created
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/%s", url, ua["email"]), nil)
	resp, err = client.Do(req)
}

func TestUserAcc(t *testing.T) {
	url := "http://localhost:8080/users"
	// this is the valid user that can get posted with no problems
	ua := map[string]interface{}{
		"email":  "kneeru@someshit.com",
		"role":   2,
		"passwd": "ranjan_wati!538",
		"name":   "Niranjan Awati",
		"phone":  "+91 5453500 5435345",
		"loc":    "Pune, 411057",
	}
	body, _ := json.Marshal(ua)
	// ++++++++++ making the request to the api to post new user

	resp, err := http.Post(url, "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexpected error making a get request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting 200 response status code")

	// +++++++++++++ now patching the user details
	ua = map[string]interface{}{
		"email": "kneeru@someshit.com",
		"name":  "Niranjan V Awati",
		"phone": "+91 654646 5435345",
		"loc":   "Pune, 411057",
	}
	body, _ = json.Marshal(ua)
	req, _ := http.NewRequest("PUT", fmt.Sprintf("%s/%s", url, ua["email"]), bytes.NewBuffer(body))
	resp, err = (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error making a put request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting 200 response status code")

	// +++++++++++++ we are patching the password of the user
	ua = map[string]interface{}{
		"email":  "kneeru@someshit.com",
		"passwd": "anjan_wati!53",
	}
	body, _ = json.Marshal(ua)
	req, _ = http.NewRequest("PATCH", fmt.Sprintf("%s/%s", url, ua["email"]), bytes.NewBuffer(body))
	resp, err = (&http.Client{}).Do(req)
	assert.Nil(t, err, "Unexpected error making a patch request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting 200 response status code")

	// +++++++++++++++++ then trying to post the same user again
	resp, err = http.Post(url, "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexpected error making a get request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, 400, resp.StatusCode, "Was expecting 200 response status code")
	bb, _ := ioutil.ReadAll(resp.Body)
	t.Log(string(bb))
	resp.Body.Close()

	// ++++++++++++++++++++++++
	// now trying to inject a invalid user
	ua = map[string]interface{}{
		"email":  "kneeru@someshit",
		"role":   2,
		"passwd": "ranjan_wati@538",
		"name":   "Niranjan Awati",
		"phone":  "+91 5453500 5435345",
		"loc":    "Pune, 411057",
	}
	body, _ = json.Marshal(ua)
	resp, err = http.Post(url, "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexpected error making a post request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, 400, resp.StatusCode, "Was expecting 400 response status code")

	// ++++++++++++++++++++
	// now trying to inject a user account with invalid password

	ua = map[string]interface{}{
		"email":  "kneeru@someshit.com",
		"role":   2,
		"passwd": "ranjan_wati@538fsdfdsfsdfdsfsfsdfsdf",
		"name":   "Niranjan Awati",
		"phone":  "+91 5453500 5435345",
		"loc":    "Pune, 411057",
	}
	body, _ = json.Marshal(ua)
	resp, err = http.Post(url, "application/json", bytes.NewBuffer(body))
	assert.Nil(t, err, "Unexpected error making a post request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, 400, resp.StatusCode, "Was expecting 400 response status code")

	// +++++++++++++ now clearing the user using the delete request
	client := &http.Client{}
	req, _ = http.NewRequest("DELETE", fmt.Sprintf("%s/%s", url, ua["email"]), nil)
	resp, err = client.Do(req)
	assert.Nil(t, err, "Unexpected error making a delete request")
	assert.NotNil(t, resp, "Unexpected nil response from server")
	assert.Equal(t, 200, resp.StatusCode, "Was expecting 200 response status code")
}
