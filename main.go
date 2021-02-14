package main

import (
	"bufio"
	"os"

	"github.com/eensymachines-in/authapi/handlers"
	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"
)

func init() {
	// log.SetFormatter(&log.JSONFormatter{})
	log.SetFormatter(&log.TextFormatter{
		DisableColors: false,
		FullTimestamp: true,
	})
	log.SetReportCaller(true)
	log.SetOutput(os.Stdout)
	log.SetLevel(log.TraceLevel)
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
	log.Infof("The authentication secret %s", os.Getenv("AUTH_SECRET"))
	// ++++++++++++++++++++ reading in the refresh secret
	line, _, err = reader.ReadLine()
	if err != nil {
		log.Error("Error reading the refr secret from file")
	}
	os.Setenv("REFR_SECRET", string(line))
	log.Infof("The refresh secret %s", os.Getenv("REFR_SECRET"))

}
func main() {
	r := gin.Default()
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	r.Use(CORS)
	// devices group
	devices := r.Group("/devices")
	devices.Use(lclDbConnect())

	devices.POST("", handlers.HandlDevices)          // when creating new registrations
	devices.GET("/:serial", handlers.HandlDevices)   // when getting existing registrations
	devices.PATCH("/:serial", handlers.HandlDevices) // when modifying existing registration

	// Users group
	users := r.Group("/users")
	users.Use(lclDbConnect())

	users.POST("", handlers.HndlUsers)
	users.GET("/:email", handlers.HandlUser)
	// +++++++++++ modification of the account details needs to verify if the user in the param is same as in the token
	users.Use(tokenParse()).Use(verifyUser()).PUT("/:email", handlers.HandlUser)
	users.Use(tokenParse()).Use(verifyUser()).PATCH("/:email", handlers.HandlUser)
	// +++++++++ to delete an account you need elevated permission
	users.Use(tokenParse()).Use(verifyRole(2)).DELETE("/:email", handlers.HandlUser)

	// will handle only authentication
	auths := r.Group("/authenticate")
	auths.Use(lclDbConnect()).Use(lclCacConnect()).POST("/:email", handlers.HandlAuth)

	// /authorize/?lvl=2
	// /authorize/?refresh=true
	authrz := r.Group("/authorize")
	authrz.Use(lclCacConnect()).Use(tokenParse()).GET("", handlers.HndlAuthrz)
	authrz.Use(tokenParse()).DELETE("", handlers.HndlAuthrz)
	log.Fatal(r.Run(":8080"))
}
