package foxsecslackbot

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
	"go.mozilla.org/mozlogrus"
)

var (
	globalConfig Config
	client       = &http.Client{
		Timeout: 10 * time.Second,
	}
	KEYNAME = os.Getenv("KMS_KEYNAME")
)

const (
	EMAIL_CHAR_SET             = "UTF-8"
	WHITELIST_IP_SLASH_COMMAND = "whitelist_ip"
)

func init() {
	mozlogrus.Enable("foxsec-slack-bot")
	InitConfig()
}

type Config struct {
	slackSigningSecret string
	slackAuthToken     string
	slackClient        *slack.Client
	escalationEmail    string
	awsSecretAccessKey string
	awsAccessKeyId     string
	awsRegion          string
	sesSenderEmail     string
	sesClient          *ses.SES
}

func InitConfig() error {
	kms, err := common.NewKMSClient()
	if err != nil {
		log.Fatalf("Could not create kms client. Err: %s", err)
	}

	globalConfig.slackSigningSecret, err = kms.DecryptSymmetric(KEYNAME, os.Getenv("SLACK_SIGNING_SECRET"))
	if err != nil {
		log.Fatalf("Could not decrypt slack signing secret. Err: %s", err)
	}

	globalConfig.slackAuthToken, err = kms.DecryptSymmetric(KEYNAME, os.Getenv("SLACK_AUTH_TOKEN"))
	if err != nil {
		log.Fatalf("Could not decrypt slack auth token. Err: %s", err)
	}

	globalConfig.slackClient = slack.New(globalConfig.slackAuthToken)

	globalConfig.escalationEmail = os.Getenv("ESCALATION_EMAIL")
	if globalConfig.escalationEmail == "" {
		log.Fatalf("No ESCALATION_EMAIL provided.")
	}

	globalConfig.awsRegion = os.Getenv("AWS_REGION")
	globalConfig.awsSecretAccessKey, err = kms.DecryptSymmetric(KEYNAME, os.Getenv("AWS_SECRET_ACCESS_KEY"))
	if err != nil {
		log.Fatalf("Could not decrypt aws secret access key. Err: %s", err)
	}
	globalConfig.awsAccessKeyId, err = kms.DecryptSymmetric(KEYNAME, os.Getenv("AWS_ACCESS_KEY_ID"))
	if err != nil {
		log.Fatalf("Could not decrypt aws access key id. Err: %s", err)
	}

	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(globalConfig.awsRegion),
		Credentials: credentials.NewStaticCredentials(globalConfig.awsAccessKeyId, globalConfig.awsSecretAccessKey, ""),
	})
	globalConfig.sesClient = ses.New(sess)

	return nil
}

// Send email to pagerduty using AWS SES
func escalateAlert(alert *common.Alert, db *common.DBClient) error {
	err := emailEscalation(alert)
	if err != nil {
		log.Error(err)
		return err
	}
	err = db.UpdateAlert(alert, "ESCALATED")
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}

func emailEscalation(alert *common.Alert) error {
	subject := fmt.Sprintf("[foxsec-pipeline-alert] Escalating alert - %s", alert.Summary)

	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			CcAddresses: []*string{},
			ToAddresses: []*string{
				aws.String(globalConfig.escalationEmail),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Text: &ses.Content{
					Charset: aws.String(EMAIL_CHAR_SET),
					Data:    aws.String(alert.PrettyPrint()),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(EMAIL_CHAR_SET),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(globalConfig.sesSenderEmail),
	}

	// Attempt to send the email.
	_, err := globalConfig.sesClient.SendEmail(input)

	// Display error messages if they occur.
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			switch aerr.Code() {
			case ses.ErrCodeMessageRejected:
				log.Errorf("ses.ErrCodeMessageRejected: %s", aerr.Error())
			case ses.ErrCodeMailFromDomainNotVerifiedException:
				log.Errorf("ses.ErrCodeMailFromDomainNotVerifiedException: %s", aerr.Error())
			case ses.ErrCodeConfigurationSetDoesNotExistException:
				log.Errorf("ses.ErrCodeConfigurationSetDoesNotExistException: %s", aerr.Error())
			default:
				log.Errorf("misc ses error: %s", aerr.Error())
			}
		} else {
			log.Errorf("ses error: %s", err)
		}

		return err
	}

	return nil
}

func handleAuthConfirm(req slack.InteractionCallback, db *common.DBClient) (*slack.Msg, error) {
	alertId := strings.Split(req.CallbackID, "_")[1]
	alert, err := db.GetAlert(alertId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	response := "Error responding; please contact SecOps (secops@mozilla.com)"
	if req.Actions[0].Name == "auth_yes" {
		err := db.UpdateAlert(alert, "ACKNOWLEDGED")
		if err != nil {
			log.Error(err)
		}
		response = "Thank you for responding! Alert acknowledged"
	} else if req.Actions[0].Name == "auth_no" {
		err := escalateAlert(alert, db)
		if err != nil {
			log.Error(err)
		}
		response = "Thank you for responding! Alert has been escalated to SecOps (secops@mozilla.com)"
	}

	return &slack.Msg{Text: response, ReplaceOriginal: false}, nil
}

func readInteraction(r *http.Request) (slack.InteractionCallback, error) {
	// Handle interaction callback
	buf, err := ioutil.ReadAll(r.Body)
	if err != nil {
		log.Error(err.Error())
		return slack.InteractionCallback{}, err
	}
	var req slack.InteractionCallback
	err = json.Unmarshal(buf, &req)
	if err != nil {
		log.Error(err.Error())
		return slack.InteractionCallback{}, err
	}

	return req, nil
}

func isAuthConfirm(req slack.InteractionCallback) bool {
	if strings.HasPrefix(req.CallbackID, "auth_confirmation") {
		return true
	}

	return false
}

func handleWhitelistCmd(cmd slack.SlashCommand, db *common.DBClient) (*slack.Msg, error) {
	msg := &slack.Msg{}

	splitCmd := strings.Split(cmd.Text, " ")
	ip := net.ParseIP(splitCmd[0])
	if ip == nil {
		m := fmt.Sprintf("Got invalid IP: %s", splitCmd[0])
		msg.Text = m
		return msg, errors.New(m)
	}

	expiresDur, err := time.ParseDuration(splitCmd[1])
	if err != nil {
		log.Error(err.Error())
		msg.Text = "Was unable to correctly parse duration"
		return msg, err
	}
	expiresAt := time.Now().Add(expiresDur)

	userProfile, err := globalConfig.slackClient.GetUserProfile(cmd.UserID, false)
	if err != nil {
		log.Error(err.Error())
		msg.Text = "Was unable to get your email from Slack."
		return msg, err
	}

	err = db.SaveWhitelistedIp(common.NewWhitelistedIP(ip.String(), expiresAt, userProfile.Email))
	if err != nil {
		log.Error(err.Error())
		msg.Text = "Error saving IP to whitelist"
		return msg, err
	}

	msg.Text = fmt.Sprintf("Successfully saved %s to the whitelist. Will expire at %s", ip, expiresAt)
	return msg, nil
}

func sendSlackCallback(msg *slack.Msg, responseUrl string) error {
	j, err := json.Marshal(msg)
	if err != nil {
		log.Error(err.Error())
		return err
	}
	_, err = client.Post(responseUrl, "application/json", bytes.NewBuffer(j))
	if err != nil {
		log.Error(err.Error())
		return err
	}
	return nil
}

func FoxsecSlackHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)

	// Check signature
	sv, err := slack.NewSecretsVerifier(r.Header, globalConfig.slackSigningSecret)
	if err != nil {
		log.Error(err.Error())
		return
	}
	err = sv.Ensure()
	if err != nil {
		log.Error(err.Error())
		return
	}

	db, err := common.NewDBClient()
	if err != nil {
		log.Error(err.Error())
		return
	}
	defer db.Close()

	if req, err := readInteraction(r); err == nil {
		if isAuthConfirm(req) {
			resp, err := handleAuthConfirm(req, db)
			if err != nil {
				log.Error(err.Error())
				return
			}
			log.Info(resp)

			err = sendSlackCallback(resp, req.ResponseURL)
			if err != nil {
				log.Error(err.Error())
				return
			}
		}
	} else if cmd, err := slack.SlashCommandParse(r); err == nil {
		if cmd.Command == WHITELIST_IP_SLASH_COMMAND {
			resp, err := handleWhitelistCmd(cmd, db)
			if err != nil {
				log.Error(err.Error())
				return
			}
			err = sendSlackCallback(resp, cmd.ResponseURL)
			if err != nil {
				log.Error(err.Error())
				return
			}
		}
	}

	return
}
