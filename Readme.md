### Creating a new user account 
--------

```go
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

```

### Authenticate user credentials
--------

```go
creds := map[string]interface{}{
    "email":  email,
    "passwd": passwd,
}
body, _ := json.Marshal(creds)
resp, err := http.Post(fmt.Sprintf("http://localhost:8080/authenticate/%s", creds["email"]), "application/json", bytes.NewBuffer(body))
assert.Nil(t, err, "Unexepcted error when posting a new user account")
assert.NotNil(t, resp, "Unexpected nil response from server for posting a new account")
assert.Equal(t, expected, resp.StatusCode, "Was expecting a 200 ok on posting new user account")
defer resp.Body.Close()
target := map[string]string{}
if json.NewDecoder(resp.Body).Decode(&target) != nil {
    t.Error("Failed to decode the authentication response containing tokenss")
}
```

### Updating acount details

```go
var auth string // is the authentication token as string
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
```

### Updating password for the account


```go
url := "http://localhost:8080/users"
ua := map[string]interface{}{
    "email":  email,
    "passwd": passwd,
}
body, _ := json.Marshal(ua)
req, _ := http.NewRequest("PATCH", fmt.Sprintf("%s/%s", url, ua["email"]), bytes.NewBuffer(body))
req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
resp, err := (&http.Client{}).Do(req)
```

### Authorize user
---------

```go
var auth string // authentication token as sent by the login 
req, _ := http.NewRequest("GET", "http://localhost:8080/authorize", nil)
req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
resp, err := (&http.Client{}).Do(req)
```

### Refresh user 
-----------

```go
var refr string // refresh token - please see if the auth token has not expired, that would be orphaned.
req, _ := http.NewRequest("GET", "http://localhost:8080/authorize?refresh=true", nil)
req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", refr))
resp, err := (&http.Client{}).Do(req)
defer resp.Body.Close()
target := map[string]string{}
if json.NewDecoder(resp.Body).Decode(&target) != nil {
    t.Error("Failed to decode the authentication response containing tokenss")
}
```

### Logout user 
-------

```go 
var auth, refr string // token string form that used to authorize
req, _ := http.NewRequest("DELETE", "http://localhost:8080/authorize", nil)
req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", auth))
(&http.Client{}).Do(req)
req, _ = http.NewRequest("DELETE", "http://localhost:8080/authorize?refresh=true", nil)
req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", refr))
(&http.Client{}).Do(req)
```