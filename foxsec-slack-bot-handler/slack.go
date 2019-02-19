package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"github.com/nlopes/slack"
	log "github.com/sirupsen/logrus"
)

var client = &http.Client{
	Timeout: 10 * time.Second,
}

const (
	WHITELIST_IP_SLASH_COMMAND = "whitelist_ip"
)

func handleAuthConfirm(req slack.InteractionCallback, db *DBClient) (*slack.Msg, error) {
	alertId := strings.Split(req.CallbackID, "_")[1]
	alert, err := db.getAlert(alertId)
	if err != nil {
		log.Error(err)
		return nil, err
	}

	response := "Error responding; please contact SecOps (secops@mozilla.com)"
	if req.Actions[0].Name == "auth_yes" {
		err := db.updateAlert(alert, "ACKNOWLEDGED")
		if err != nil {
			log.Error(err)
		}
		response = "Thank you for responding! Alert acknowledged"
	} else if req.Actions[0].Name == "auth_no" {
		err := db.escalateAlert(alert)
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

func handleWhitelistCmd(cmd slack.SlashCommand, db *DBClient) (*slack.Msg, error) {
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

	err = db.saveWhitelistedIp(common.NewWhitelistedIP(ip.String(), expiresAt, userProfile.Email))
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
