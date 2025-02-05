package main

import (
	"fmt"
	"time"

	"github.com/LuisSilva7/jwt-implementation/internal/jwt"
)

func main() {
	header := jwt.JWTHeader{Alg: "HS256", Typ: "JWT"}
	encodedHeader, err := jwt.ToBase64URL(header)
	if err != nil {
		fmt.Println("Error encoding header:", err)
		return
	}

	fmt.Println("Encoded Header:", encodedHeader)

	payload := jwt.JWTPayload{
		Sub:  "1234567890",
		Name: "John Doe",
		Iat:  int(time.Now().Unix()),
		Exp:  int(time.Now().Unix()) + 3600, // Expires in 1 hour
	}
	encodedPayload, err := jwt.ToBase64URL(payload)
	if err != nil {
		fmt.Println("Error encoding payload:", err)
		return
	}

	unsignedToken := encodedHeader + "." + encodedPayload
	fmt.Println("Unsigned JWT:", unsignedToken)

	// Define a secret key
	secret := "A3788AA4BEF3E3B7AF44D7AE1E172"

	signature, err := jwt.SignToken(unsignedToken, secret)
	if err != nil {
		fmt.Println("Error signing token:", err)
		return
	}

	token := unsignedToken + "." + signature
	fmt.Println("JWT Token:", token)

	validated, err := jwt.ValidateJWT(token, secret)
	if err != nil {
		fmt.Println("\nError validating token")
		return
	}

	if validated {
		fmt.Println("\nValid token")
	}
}
