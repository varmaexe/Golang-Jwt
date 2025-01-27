# Go Authentication API

This project is a web application built with Go, Gin, and MongoDB. It includes user authentication, authorization, and CRUD operations for user data.

## Project Structure

```sh
.env
controllers/
    userController.go
database/
    databaseConnection.go
go.mod
go.sum
helpers/
    authHelper.go
    tokenHelper.go
main.go
middleware/
    authMiddleware.go
models/
    userModel.go
routes/
    authRouter.go
    userRouter.go
```

## Environment Variables

The `.env` file contains the following environment variables:

- `PORT`: The port on which the server will run.
- `MONGODB_URL`: The MongoDB connection URL.
- `SECRET_KEY`: The secret key used for JWT token generation.

## Database Connection

The database connection is handled in [database/databaseConnection.go](database/databaseConnection.go). The `DBinstance` function initializes the MongoDB client, and the `OpenCollection` function opens a specific collection.

## Models

The user model is defined in [models/userModel.go](models/userModel.go). It includes fields for user information such as first name, last name, email, password, phone, user type, tokens, and timestamps.

## Helpers

### Token Helper

The [helpers/tokenHelper.go](helpers/tokenHelper.go) file contains functions for generating and validating JWT tokens:

- `GenerateAllTokens`: Generates access and refresh tokens.
- `UpdateAllTokens`: Updates the tokens in the database.
- `ValidateToken`: Validates a given token and returns the claims.

### Auth Helper

The [helpers/authHelper.go](helpers/authHelper.go) file contains functions for checking user roles and matching user types to UIDs:

- `CheckUserType`: Checks if the user type matches the required role.
- `MatchUserTypeToUid`: Ensures that regular users can only access their own data.

## Middleware

The [middleware/authMiddleware.go](middleware/authMiddleware.go) file contains the `Authenticate` middleware function, which validates the JWT token and sets the user claims in the context.

## Controllers

The [controllers/userController.go](controllers/userController.go) file contains the following handler functions:

- `Signup`: Handles user registration.
- `Login`: Handles user login.
- `GetUsers`: Retrieves a list of users (admin only).
- `GetUser`: Retrieves a specific user by ID.

## Routes

### Auth Routes

The [routes/authRouter.go](routes/authRouter.go) file defines the authentication routes:

- `POST /user/signup`: Calls the `Signup` handler.
- `POST /users/login`: Calls the `Login` handler.

### User Routes

The [routes/userRouter.go](routes/userRouter.go) file defines the user routes:

- `GET /users`: Calls the `GetUsers` handler (requires authentication).
- `GET /users/:user_id`: Calls the `GetUser` handler (requires authentication).

## Main Entry Point

The [main.go](main.go) file is the entry point of the application. It initializes the Gin router, sets up the routes, and starts the server on the specified port.

## Running the Project

1. Ensure you have Go and MongoDB installed.
2. Set up the environment variables in the `.env` file.
3. Run the following command to start the server:

```go
go run main.go
```

The server will start on the port specified in the .env file (default is 8000 if not set).