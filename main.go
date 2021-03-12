package main

import (
	"bufio"
	"flag"
	"os"

	"github.com/eensymachines-in/auth/v2"
	"github.com/eensymachines-in/authapi/handlers"
	utl "github.com/eensymachines-in/utilities"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
	"gopkg.in/mgo.v2"
)

var (
	// /var/local/authapi : is mapped on the host machine
	logFile = "/var/local/authapi/server.log"
	// Flog : determines if the direction of log output
	Flog bool
	// FVerbose :  determines the level of log
	FVerbose bool
)

func init() {
	// log file - direction and level
	utl.SetUpLog()
	flag.BoolVar(&Flog, "flog", true, "direction of log messages, set false for terminal logging. Default is true")
	flag.BoolVar(&FVerbose, "verbose", false, "Determines what level of log messages are to be output")
	// +++++++++++++++++++ reading the secrets into the environment
	file, err := os.Open("/run/secrets/auth_secrets")
	if err != nil {
		log.Errorf("Failed to read encryption secrets, please load those %s", err)
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	// ++++++++++++++++++++++++++++++++ reading in the auth secret
	line, _, err := reader.ReadLine()
	if err != nil {
		log.Error("Error reading the auth secret from file")
	}
	os.Setenv("AUTH_SECRET", string(line))
	// log.Infof("The authentication secret %s", os.Getenv("AUTH_SECRET"))
	// ++++++++++++++++++++ reading in the refresh secret
	line, _, err = reader.ReadLine()
	if err != nil {
		log.Error("Error reading the refr secret from file")
	}
	os.Setenv("REFR_SECRET", string(line))
	// log.Infof("The refresh secret %s", os.Getenv("REFR_SECRET"))
	// ++++++++++ Now reading the admin secret and creating a user if not already created
	file1, err := os.Open("/run/secrets/admin_secret")
	if err != nil {
		log.Errorf("Failed to read the admin.secret, kindly load them before you run the container %s", err)
	}
	defer file1.Close()
	reader = bufio.NewReader(file1)
	line, _, err = reader.ReadLine()
	if err != nil {
		log.Error("Error reading the admin secret file, check the file for the expected contents")
		return
	}
	os.Setenv("ADMIN_SECRET", string(line))
}

// seedAdminUserAccount: without atleast one admin user there is no scope for adding accounts any further
// will check for if already registered, if not then registers the same st away
func seedAdminUserAccount() error {
	session, err := mgo.Dial("srvmongo")
	if err != nil {
		log.Fatal("Could not seed the admin to the database")
	}
	ua := &auth.UserAccounts{Collection: session.DB("autolumin").C("userreg")}
	if ua.IsRegistered("kneerunjun@gmail.com") {
		return nil
	}
	// +++++++++ else we would want to register the user account
	// the password shall be picked from the environment of the guest machine
	// the host machine shall have the file which is then loaded onto the guest machine at the run
	// pushing the same onto the host machine though would be the job of the CI/CD
	return ua.InsertAccount(&auth.UserAccDetails{Name: "Niranjan", Phone: "+918390906860", Loc: "Pune", UserAcc: auth.UserAcc{
		Email:  "kneerunjun@gmail.com",
		Passwd: os.Getenv("ADMIN_SECRET"),
		Role:   2,
	}})

}
func main() {
	// Setting the log direction and the level of log
	flag.Parse()
	closeLogFile := utl.CustomLog(Flog, FVerbose, logFile)
	defer closeLogFile()
	log.WithFields(log.Fields{
		"flog":    Flog,
		"verbose": FVerbose,
	}).Info("Starting authapi module")

	//+++++++++++ now inserting the admin user if not already exists
	if err := seedAdminUserAccount(); err != nil {
		log.Fatalf("Failed to insert admin account seed, cannot continue %s", err)
	}
	// ++++++++++++ Now setting up the routes
	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()
	r.Use(CORS)
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})
	// devices group
	devices := r.Group("/devices")
	devices.Use(lclDbConnect())

	devices.GET("", handlers.HandlDevices)  // filtered list of devices /devices?black=true
	devices.POST("", handlers.HandlDevices) // when creating new registrations

	devices.GET("/:serial", handlers.HandlDevice) // when getting existing registrations
	// When the device registration has to be modified or deleted
	devices.PATCH("/:serial", tokenParse(), verifyRole(1), handlers.HandlDevice)
	devices.DELETE("/:serial", tokenParse(), verifyRole(2), handlers.HandlDevice)

	// Users group
	users := r.Group("/users")
	users.Use(lclDbConnect())

	users.POST("", handlers.HndlUsers)                             // new user registrations
	users.GET("", tokenParse(), verifyRole(2), handlers.HndlUsers) // enlisting the user accounts
	users.GET("/:email", handlers.HandlUser)                       // get user registration details
	users.GET("/:email/devices", handlers.HandlUsrDevices)         // get all the user devices

	users.PUT("/:email", tokenParse(), verifyUser(), handlers.HandlUser) // changing the user account details
	users.PATCH("/:email", b64UserCredsParse(), handlers.HandlUser)      // update password
	// +++++++++ to delete an account you need elevated permission and authentication token
	users.DELETE("/:email", tokenParse(), verifyRole(2), handlers.HandlUser)

	// will handle only authentication
	auths := r.Group("/authenticate")
	auths.Use(lclCacConnect()).Use(lclDbConnect()).Use(b64UserCredsParse())
	auths.POST("/:email", handlers.HandlAuth)

	// /authorize/?lvl=2
	// /authorize/?refresh=true
	authrz := r.Group("/authorize")
	authrz.Use(lclCacConnect()).Use(tokenParse())
	authrz.GET("", handlers.HndlAuthrz)    // verifying the token ?lvl=2 ?refresh=true
	authrz.DELETE("", handlers.HndlAuthrz) // logging the token out from the cache
	log.Fatal(r.Run(":8080"))
}
