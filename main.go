package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	api "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
)

func main() {
	setUpCmd()
}

func setUpCmd() {
	loginCmd := flag.NewFlagSet("login", flag.ExitOnError)
	logoutCmd := flag.NewFlagSet("logout", flag.ExitOnError)
	emailCmd := flag.NewFlagSet("email", flag.ExitOnError)
	if len(os.Args) == 1 {
		fmt.Println("This command has login, logout, email commands. Please use them.")
		return
	}

	switch os.Args[1] {
	case "login":
		loginCmd.Parse(os.Args[2:])
		login()
	case "logout":
		logoutCmd.Parse(os.Args[2:])
		logout()
	case "email":
		emailCmd.Parse(os.Args[2:])
		getEmail()
	default:
		flag.Usage()
	}
}

func loadSecrets() (string, string, error) {
	id := os.Getenv("CLIENT_ID")
	secret := os.Getenv("CLIENT_SECRET")
	if id == "" || secret == "" {
		return "", "", errors.New("CLIENT_ID & CLIENT_SECRET are required in env")
	}

	return id, secret, nil
}

func login() {
	id, secret, err := loadSecrets()
	if err != nil {
		log.Fatalln(err)
	}

	auth := NewOAuth(
		id,
		secret,
		[]string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
	)

	ctx := context.Background()

	log.Println("Login with browser")
	if err := auth.Authorize(ctx); err != nil {
		log.Fatalln(err)
	}
	if err := auth.SaveToken(); err != nil {
		log.Println(err)
	}
	log.Println("Get & save token")
}

func logout() {
	auth := NewOAuth("", "", nil)
	auth.Revoke()
}

func getEmail() {
	id, secret, err := loadSecrets()
	if err != nil {
		log.Fatalln(err)
	}
	auth := NewOAuth(id, secret, nil)
	if err := auth.LoadToken(); err != nil {
		log.Println(err)
		log.Fatalln("Please login")
	}

	ctx := context.Background()
	client := auth.Client(ctx)
	email, err := getMailAddress(ctx, client)
	if err != nil {
		log.Fatalln(err)
	}
	fmt.Printf("Your email address is %s\n", email)

	// NOTE: It is not good. See a comment in saveTokenToFile().
	if err := auth.SaveToken(); err != nil {
		log.Println(err)
	}
}

func getMailAddress(ctx context.Context, client *http.Client) (string, error) {
	service, err := api.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return "", err
	}
	userInfo, err := service.Tokeninfo().Context(ctx).Do()
	if err != nil {
		return "", err
	}

	return userInfo.Email, nil
}
