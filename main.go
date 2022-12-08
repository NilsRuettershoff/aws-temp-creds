package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"gopkg.in/ini.v1"
)

// keeps all essential data
type Core struct {
	role     string
	region   string
	profile  string
	token    string
	mfa      string
	credName string
	credFile string
	sessName string
	duration int
	cfg      *ini.File
}

func newCore() *Core {
	c := &Core{}
	c.getCredFile()
	return c
}

func main() {
	c := newCore()
	flag.StringVar(&c.role, "role", "", "role to assume")
	flag.StringVar(&c.region, "region", "eu-central-1", "region to assume")
	flag.StringVar(&c.profile, "profile", "default", "aws profile to use to assume role")
	flag.StringVar(&c.token, "token", "000000", "mfa temp token")
	flag.StringVar(&c.mfa, "mfa", "", "mfa arn")
	flag.StringVar(&c.credName, "cred-name", "", "the name of the credentials to use ")
	flag.StringVar(&c.sessName, "session-name", "notset", "optional: set custom session name")
	flag.IntVar(&c.duration, "duration", 3600, "optional: sets session duration")
	flag.Parse()
	c.checkToken()
	failIfNotSet(&c.role, "please define role")
	failIfNotSet(&c.region, "please define region")
	failIfNotSet(&c.profile, "please define profile")
	failIfNotSet(&c.mfa, "please provide token")
	failIfNotSet(&c.credName, "please provide token")
	var err error
	c.cfg, err = c.getCurrentCreds()
	if err != nil {
		log.Printf("unable to open aws credential file: %v", err)
		os.Exit(1)
	}
	err = c.getAndWriteTempCreds()
	if err != nil {
		log.Printf("unable get and write temp creds: %v", err)
		os.Exit(1)
	}
}

// open creds ini file
func (c *Core) getCurrentCreds() (cfg *ini.File, err error) {
	// todo imlement improved error handling/reporting

	cfg, err = ini.Load(c.credFile)
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// retrieve and write temp creds
func (c *Core) getAndWriteTempCreds() (err error) {
	s := session.Must(session.NewSession(&aws.Config{
		Region:                        aws.String(c.region),
		Credentials:                   credentials.NewSharedCredentials("", c.profile),
		CredentialsChainVerboseErrors: aws.Bool(true)}))

	var username string
	usr, err := user.Current()
	if err != nil {
		username = "Temp"
	}
	username = usr.Username

	// on coparate windows machines usernames can contain '\' which is not allowed in sessioname
	b := "\\"
	if strings.Contains(username, b) {
		parts := strings.Split(username, b)
		username = parts[len(parts)-1]
	}

	if c.sessName == "notset" || c.sessName == "" {
		c.sessName = fmt.Sprintf("%sSession", username)
	}

	input := &sts.AssumeRoleInput{
		DurationSeconds: aws.Int64(int64(c.duration)),
		SerialNumber:    aws.String(c.mfa),
		TokenCode:       aws.String(c.token),
		RoleArn:         aws.String(c.role),
		RoleSessionName: aws.String(c.sessName),
	}
	svc := sts.New(s)
	result, err := svc.AssumeRole(input)
	if err != nil {
		return err
	}

	c.cfg.Section(c.credName).Key("aws_access_key_id").SetValue(*result.Credentials.AccessKeyId)
	c.cfg.Section(c.credName).Key("aws_secret_access_key").SetValue(*result.Credentials.SecretAccessKey)
	c.cfg.Section(c.credName).Key("aws_session_token").SetValue(*result.Credentials.SessionToken)
	c.cfg.Section(c.credName).Key("aws_session_expiration").SetValue(result.Credentials.Expiration.Format(time.RFC3339Nano))

	c.cfg.SaveTo(c.credFile)

	return nil
}

func (c *Core) getCredFile() (err error) {
	usr, err := user.Current()
	if err != nil {
		return nil
	}
	c.credFile = fmt.Sprintf("%s/.aws/credentials", usr.HomeDir)
	return nil
}

// asks for token if not provided, exits in case of error
func (c *Core) checkToken() {
	if c.token != "000000" {
		return
	}
	fmt.Print("please provide mfa token: ")
	fmt.Scanln(&c.token)
	return
}

// failIfNotSet checks if the given argument is defined, if not it exists the programm with failmsg
func failIfNotSet(argument *string, failmsg string) {
	if argument == nil || *argument == "" {
		fmt.Println(failmsg)
		os.Exit(1)
	}
}
