package controllers

import (
	"context"
	"example/database"
	helper "example/helpers"
	"example/models"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = database.OpenCollection(database.Client, "user")
var validate = validator.New()

func HashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func VerifyPassword(userPassword string, providedPassword string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(providedPassword), []byte(userPassword))
	check := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("email of password is incorrect")
		check = false
	}
	return check, msg
}

func Signup() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Setting up a context with a timeout for database queries
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel() // Ensure the cancel function is called at the end to release resources

		var user models.User

		// Bind incoming JSON data to the 'user' struct
		// This will automatically populate the struct fields based on the JSON payload in the request
		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // Return a 400 status if binding fails
			return
		}

		// Validate the struct according to the provided tags (like required, min, max, etc.)
		validationErr := validate.Struct(user)
		if validationErr != nil {
			var errors []string
			// Iterate over the validation errors and create a more readable error message
			for _, err := range validationErr.(validator.ValidationErrors) {
				errors = append(errors, fmt.Sprintf("Field '%s' failed validation: %s", err.Field(), err.Tag()))
			}
			c.JSON(http.StatusBadRequest, gin.H{"errors": errors}) // Return 400 with validation errors
			return
		}

		// Checking if the email already exists in the database
		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Panic(err) // Log the error for debugging
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking for the email"})
			return
		}

		// Validate that the password is provided and its length is at least 6 characters
		if user.Password == nil || len(*user.Password) < 6 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Password cannot be empty and must be at least 6 characters long"})
			return
		}

		// Hash the password before storing it in the database (to enhance security)
		password := HashPassword(*user.Password)
		user.Password = &password // Update the password field with the hashed version

		// Checking if the phone number already exists in the database
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Panic(err) // Log the error for debugging
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while checking for the phone"})
			return
		}

		// If a matching email or phone number already exists, return a 400 error with a specific message
		if count > 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "This email or phone number already exists"})
			return
		}

		// Set the creation and update timestamps for the user record
		// The RFC3339 format is commonly used for time in API responses
		user.Created_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))
		user.Updated_at, _ = time.Parse(time.RFC3339, time.Now().Format(time.RFC3339))

		// Generate a new ObjectId for the user
		user.ID = primitive.NewObjectID()
		user.User_id = user.ID.Hex() // Convert the ObjectId to a string to store as user_id

		// Generate JWT tokens for the user (authentication and refresh tokens)
		token, refreshToken, _ := helper.GenerateAllTokens(*user.Email, *user.First_name, *user.Last_name, *user.User_type, user.User_id)
		user.Token = &token
		user.Refresh_token = &refreshToken

		// Insert the newly created user record into the database
		resultInsertionNumber, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User item was not created"}) // Return error if insert fails
			return
		}

		// Return a successful response with the inserted record details (e.g., the inserted user)
		c.JSON(http.StatusOK, resultInsertionNumber)
	}
}

func Login() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		defer cancel()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email or password is incorrect"})
			return
		}

		passwordIsValid, msg := VerifyPassword(*user.Password, *foundUser.Password)
		defer cancel()
		if passwordIsValid != true {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		if foundUser.Email == nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		}
		token, refreshToken, _ := helper.GenerateAllTokens(*foundUser.Email, *foundUser.First_name, *foundUser.Last_name, *foundUser.User_type, foundUser.User_id)
		helper.UpdateAllTokens(token, refreshToken, foundUser.User_id)
		err = userCollection.FindOne(ctx, bson.M{"user_id": foundUser.User_id}).Decode(&foundUser)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, foundUser)
	}
}

func GetUsers() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check user type
		if err := helper.CheckUserType(c, "ADMIN"); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Set up context with timeout
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		// Parse recordPerPage with a default value of 10
		recordPerPage, err := strconv.Atoi(c.Query("recordPerPage"))
		if err != nil || recordPerPage < 1 {
			recordPerPage = 10
		}

		// Parse page with a default value of 1
		page, err := strconv.Atoi(c.Query("page"))
		if err != nil || page < 1 {
			page = 1
		}

		// Calculate startIndex based on page and recordPerPage
		startIndex := (page - 1) * recordPerPage

		// Optional: Override startIndex if provided in the query
		if queryStartIndex := c.Query("startIndex"); queryStartIndex != "" {
			startIndex, err = strconv.Atoi(queryStartIndex)
			if err != nil {
				c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid startIndex value"})
				return
			}
		}

		// MongoDB aggregation pipeline
		matchStage := bson.D{{"$match", bson.D{}}} // Match all users
		groupStage := bson.D{
			{"$group", bson.D{
				{"_id", nil},
				{"total_count", bson.D{{"$sum", 1}}},
				{"data", bson.D{{"$push", "$$ROOT"}}},
			}},
		}
		projectStage := bson.D{
			{"$project", bson.D{
				{"_id", 0},
				{"total_count", 1},
				{"user_items", bson.D{{"$slice", bson.A{"$data", startIndex, recordPerPage}}}},
			}},
		}

		// Execute the aggregation pipeline
		cursor, err := userCollection.Aggregate(ctx, mongo.Pipeline{matchStage, groupStage, projectStage})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while listing user items"})
			return
		}

		// Parse the results into a slice
		var results []bson.M
		if err = cursor.All(ctx, &results); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Error occurred while parsing user items"})
			return
		}

		// Return the first result if available
		if len(results) > 0 {
			c.JSON(http.StatusOK, results[0])
		} else {
			c.JSON(http.StatusOK, gin.H{"message": "No users found"})
		}
	}
}

func GetUser() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		userID := ctx.Param("user_id")

		if err := helper.MatchUserTypeToUid(ctx, userID); err != nil {
			ctx.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}
		var c, cancel = context.WithTimeout(context.Background(), 100*time.Second)

		var user models.User
		err := userCollection.FindOne(c, bson.M{"user_id": userID}).Decode(&user)
		defer cancel()
		if err != nil {
			ctx.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		ctx.JSON(http.StatusOK, user)
	}
}
