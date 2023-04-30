package authen

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/golang-jwt/jwt/v4"
)

var sampleSecretKey = []byte("SecretKey")

func generateJWT(u Credentials) (string, error) {
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["exp"] = time.Now().Add(10 * time.Minute)
	claims["authorized"] = true
	claims["user"] = u.Username
	tokenString, err := token.SignedString(sampleSecretKey)
	if err != nil {
		return "Signing Error", err
	}

	return tokenString, nil
}

func getHome(c *gin.Context) {
	var token = c.Request.Header["Token"]
	fmt.Print(token)
	c.IndentedJSON(http.StatusOK, "Hello")
}

var users = []Credentials{}

type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

func validateUser(u1 Credentials, u2 Credentials) bool {
	return u1.Username == u2.Username && u1.Password == u2.Password
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

func GetUpAuthenRouter(router *gin.Engine) {
	router.POST("/signin", sigin)
	router.POST("/signup", sigup)
	router.GET("/home", getHome)
}

func sigup(c *gin.Context) {

	var newUser Credentials

	if err := c.BindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, u := range users {
		if u.Username == newUser.Username {
			c.JSON(http.StatusBadRequest, gin.H{"message": "user name is existed: "})

			return
		}

	}

	users = append(users, newUser)

	c.JSON(http.StatusOK, gin.H{"message": "created username: " + newUser.Username})

}

func sigin(c *gin.Context) {

	var signinUser Credentials

	if err := c.BindJSON(&signinUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	for _, u := range users {
		if u.Username == signinUser.Username {
			if validateUser(u, signinUser) {
				token, err := generateJWT(u)

				if err != nil {
					c.JSON(http.StatusInternalServerError, gin.H{"message": "StatusInternalServerError",
						"error": err.Error(),
						"token": token,
					})
					return
				}

				c.JSON(http.StatusOK, gin.H{"message": "login success!",
					"token": token,
				})
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"message": "StatusUnauthorized"})
			return
		}

	}

	c.JSON(http.StatusUnauthorized, gin.H{"message": "StatusUnauthorized"})
}

func Main() {
	var u = Credentials{
		Username: "VinhNT",
		Password: "123123",
	}
	token, err := generateJWT(u)

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println("token : " + token)

}
