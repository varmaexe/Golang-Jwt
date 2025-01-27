package helpers

import (
	"errors"
	"fmt"

	"github.com/gin-gonic/gin"
)

func CheckUserType(ctx *gin.Context, role string) (err error) {
	// Get the user_type from the context
	userType, exists := ctx.Get("user_type")
	if !exists {
		// Handle the case where user_type is not set in context
		return errors.New("user type not found in context")
	}

	fmt.Println("User Type from Context:", userType) // Debug log

	// Check if the user type matches the required role
	if userType != role {
		// Return an unauthorized error if roles don't match
		return errors.New("unauthorized to access this resource")
	}

	// Return nil if the user type matches the required role
	return nil
}

func MatchUserTypeToUid(ctx *gin.Context, userID string) (err error) {
	// Extract the user type and UID from the context (set during authentication)
	userType := ctx.GetString("user_type")
	uid := ctx.GetString("uid")
	err = nil

	// If the user is a regular user, ensure they can only access their own data
	if userType == "USER" && uid != userID {
		// Unauthorized if the UID does not match the userID in the URL
		err = errors.New("unauthorized to access this resource")
		return err
	}

	// If the user is an admin, they can access any user's data, no further check required
	if userType == "ADMIN" {
		return nil
	}

	// If the user is neither an admin nor a valid user, we call CheckUserType
	// This is an additional check for admin-level actions, based on your use case
	err = CheckUserType(ctx, userID)

	return err
}
