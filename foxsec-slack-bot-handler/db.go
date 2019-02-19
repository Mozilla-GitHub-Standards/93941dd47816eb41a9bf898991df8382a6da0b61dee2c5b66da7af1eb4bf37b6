package main

import (
	"context"

	"github.com/mozilla-services/foxsec-pipeline-contrib/common"

	"cloud.google.com/go/datastore"
	log "github.com/sirupsen/logrus"
)

const (
	ALERT_KIND = "alert"
	IP_KIND    = "whitelisted_ip"
)

type DBClient struct {
	dsClient *datastore.Client
}

func (db *DBClient) whitelistedIpKey(ip string) *datastore.Key {
	return datastore.NameKey(IP_KIND, ip, nil)
}

func (db *DBClient) saveWhitelistedIp(whitelistedIp *common.WhitelistedIP) error {
	_, err := db.dsClient.Put(context.TODO(), db.whitelistedIpKey(whitelistedIp.IP), whitelistedIp)
	return err
}

func (db *DBClient) alertKey(alertId string) *datastore.Key {
	return datastore.NameKey(ALERT_KIND, alertId, nil)
}

func (db *DBClient) getAlert(alertId string) (*common.Alert, error) {
	var alert common.Alert
	err := db.dsClient.Get(context.TODO(), db.alertKey(alertId), &alert)
	if err != nil {
		log.Error(err)
		return nil, err
	}
	return &alert, nil
}

func (db *DBClient) updateAlert(alert *common.Alert, status string) error {
	tx, err := db.dsClient.NewTransaction(context.TODO())
	if err != nil {
		log.Errorf("updateAlert: %v", err)
		return err
	}

	found := false
	for _, am := range alert.Metadata {
		if am.Key == "status" {
			am.Value = status
			found = true
		}
	}
	//handle case where there is no status
	if !found {
		alert.Metadata = append(alert.Metadata, common.AlertMeta{Key: "status", Value: status})
	}

	if _, err := tx.Put(db.alertKey(alert.Id), alert); err != nil {
		log.Errorf("updateAlert tx.Put: %v", err)
		return err
	}
	if _, err := tx.Commit(); err != nil {
		log.Errorf("updateAlert tx.Commit: %v", err)
		return err
	}
	return nil
}

// Send email to pagerduty using AWS SES
func (db *DBClient) escalateAlert(alert *common.Alert) error {
	err := emailEscalation(alert)
	if err != nil {
		log.Error(err)
		return err
	}
	err = db.updateAlert(alert, "ESCALATED")
	if err != nil {
		log.Error(err)
		return err
	}
	return nil
}
