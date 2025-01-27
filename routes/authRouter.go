package routes

import (
	controller "github.com/varmaexe/golang-jwt/controllers"

	"github.com/gin-gonic/gin"
)

func AuthRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.POST("user/signup", controller.Signup())
	incomingRoutes.POST("users/login", controller.Login())
}
