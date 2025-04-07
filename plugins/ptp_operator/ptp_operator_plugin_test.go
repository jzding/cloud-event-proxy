// Copyright 2020 The Cloud Native Events Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build unittests
// +build unittests

package main

import (
	"fmt"
	"log"
	"os"
	"path"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/redhat-cne/cloud-event-proxy/pkg/common"
	"github.com/redhat-cne/cloud-event-proxy/pkg/plugins"
	"github.com/redhat-cne/cloud-event-proxy/plugins/ptp_operator/metrics"
	"github.com/redhat-cne/cloud-event-proxy/plugins/ptp_operator/ptp4lconf"
	"github.com/redhat-cne/cloud-event-proxy/plugins/ptp_operator/stats"
	ptpTypes "github.com/redhat-cne/cloud-event-proxy/plugins/ptp_operator/types"
	restapi "github.com/redhat-cne/rest-api"
	"github.com/redhat-cne/sdk-go/pkg/channel"
	"github.com/redhat-cne/sdk-go/pkg/event/ptp"
	ptpEvent "github.com/redhat-cne/sdk-go/pkg/event/ptp"
	"github.com/redhat-cne/sdk-go/pkg/types"
	v1event "github.com/redhat-cne/sdk-go/v1/event"
	"github.com/stretchr/testify/assert"

	v1pubsub "github.com/redhat-cne/sdk-go/v1/pubsub"
)

var (
	wg                sync.WaitGroup
	server            *restapi.Server
	scConfig          *common.SCConfiguration
	channelBufferSize int = 10
	storePath             = "../../.."
	apiPort           int = 8990
	c                 chan os.Signal
	pubsubTypes       map[ptpEvent.EventType]*ptpTypes.EventPublisherType
	ptpEventManager   *metrics.PTPEventManager
)

var logPtp4lConfig = &ptp4lconf.PTP4lConfig{
	Name:    "ptp4l.0.config",
	Profile: "grandmaster",
	Interfaces: []*ptp4lconf.PTPInterface{
		{
			Name:     "ens2f0",
			PortID:   1,
			PortName: "port 1",
			Role:     2, //master
		},
		{
			Name:     "ens7f0",
			PortID:   2,
			PortName: "port 3",
			Role:     2, // master
		},
	},
}

func setup() {
	scConfig = &common.SCConfiguration{
		EventInCh:  make(chan *channel.DataChan, channelBufferSize),
		EventOutCh: make(chan *channel.DataChan, channelBufferSize),
		CloseCh:    make(chan struct{}),
		APIPort:    apiPort,
		APIPath:    "/api/test-cloud/",
		APIVersion: "2.0",
		PubSubAPI:  v1pubsub.GetAPIInstance(storePath),
		StorePath:  storePath,
		TransportHost: &common.TransportHost{
			Type: common.HTTP,
			URL:  "localhost:8089",
			Host: "localhost",
			Port: 8089,
			Err:  nil,
		},
		BaseURL: nil,
	}

	ptpEventManager = metrics.NewPTPEventManager(resourcePrefix, InitPubSubTypes(scConfig), "testnode", scConfig)
	ptpEventManager.MockTest(true)

	ptpEventManager.AddPTPConfig(ptpTypes.ConfigName(logPtp4lConfig.Name), logPtp4lConfig)

	statsMaster := stats.NewStats(logPtp4lConfig.Name)
	statsMaster.SetOffsetSource("master")
	statsMaster.SetProcessName("ts2phc")
	statsMaster.SetAlias("ens2fx")

	statsSlave := stats.NewStats(logPtp4lConfig.Name)
	statsSlave.SetOffsetSource("phc")
	statsSlave.SetProcessName("phc2sys")
	statsSlave.SetLastSyncState("LOCKED")
	statsSlave.SetClockClass(0)

	ptpEventManager.Stats[ptpTypes.ConfigName(logPtp4lConfig.Name)] = make(stats.PTPStats)
	ptpEventManager.Stats[ptpTypes.ConfigName(logPtp4lConfig.Name)][ptpTypes.IFace("master")] = statsMaster
	ptpEventManager.Stats[ptpTypes.ConfigName(logPtp4lConfig.Name)][ptpTypes.IFace("CLOCK_REALTIME")] = statsSlave
	ptpEventManager.Stats[ptpTypes.ConfigName(logPtp4lConfig.Name)][ptpTypes.IFace("ens2f0")] = statsMaster
	ptpEventManager.Stats[ptpTypes.ConfigName(logPtp4lConfig.Name)][ptpTypes.IFace("ens7f0")] = statsSlave

	metrics.RegisterMetrics("mynode")
}

func teardown() {
	_ = scConfig.PubSubAPI.DeleteAllPublishers()
	_ = scConfig.PubSubAPI.DeleteAllSubscriptions()
}

func TestMain(m *testing.M) {
	setup()
	c = make(chan os.Signal)
	common.StartPubSubService(scConfig)
	pubsubTypes = InitPubSubTypes(scConfig)
	teardown()
	os.Exit(m.Run())
}

// Test_StartWithHTTP ...
func Test_StartWithHTTP(t *testing.T) {
	os.Setenv("NODE_NAME", "test_node")
	scConfig.TransportHost = &common.TransportHost{
		Type:   0,
		URL:    "http://localhost:9096",
		Host:   "",
		Port:   0,
		Scheme: "",
		Err:    nil,
	}
	scConfig.TransportHost.ParseTransportHost()
	pl := plugins.Handler{Path: "../../plugins"}

	defer teardown()
	scConfig.CloseCh = make(chan struct{})
	scConfig.PubSubAPI.EnableTransport()
	log.Printf("loading http with host %s", scConfig.TransportHost.Host)
	wg := sync.WaitGroup{}
	httpTransportInstance, err := pl.LoadHTTPPlugin(&wg, scConfig, nil, nil)
	if err != nil {
		t.Skipf("http.Dial(%#v): %v", httpTransportInstance, err)
	}

	// build your client
	//CLIENT SUBSCRIPTION: create a subscription to consume events
	endpointURL := fmt.Sprintf("%s%s", scConfig.BaseURL, "dummy")
	for _, pTypes := range pubsubTypes {
		sub := v1pubsub.NewPubSub(types.ParseURI(endpointURL), path.Join(resourcePrefix, "test_node", string(pTypes.Resource)), scConfig.APIVersion)
		sub, _ = common.CreateSubscription(scConfig, sub)
		assert.NotEmpty(t, sub.ID)
		assert.NotEmpty(t, sub.URILocation)
		pTypes.PubID = sub.ID
		pTypes.Pub = &sub
	}
	log.Printf("created subscriptions")

	// start ptp plugin
	//err = Start(&wg, scConfig, nil)
	err = pl.LoadPTPPlugin(&wg, scConfig, nil)
	assert.Nil(t, err)
	log.Printf("started ptpPlugin")
	for _, pTypes := range pubsubTypes {
		e := v1event.CloudNativeEvent()
		ce, _ := v1event.CreateCloudEvents(e, *pTypes.Pub)
		ce.SetSource(pTypes.Pub.Resource)
		v1event.SendNewEventToDataChannel(scConfig.EventInCh, fmt.Sprintf("%s", pTypes.Pub.Resource), ce)
	}
	log.Printf("waiting for Event Chan")
	//EventData := <-scConfig.EventOutCh // status updated
	//assert.Equal(t, channel.EVENT, EventData.Type)

	close(scConfig.CloseCh) // close the channel
	pubs := scConfig.PubSubAPI.GetPublishers()
	assert.Equal(t, 7, len(pubs))
	subs := scConfig.PubSubAPI.GetSubscriptions()
	assert.Equal(t, 7, len(subs))
}

func TestGetCurrentStatOverrideFn(t *testing.T) {

	addr := "/sync/ptp-status/lock-state"
	out := channel.DataChan{
		Address:  addr,
		ClientID: uuid.New(),
		Status:   channel.NEW,
		Type:     channel.STATUS,
	}

	eventType := ptp.SyncStateChange
	eventSource := ptp.SyncStatusState
	data := eventManager.GetPTPEventsData(ptp.FREERUN, 0, "event-not-found", eventType)
	out.Data, _ = eventManager.GetPTPCloudEvents(*data, eventType)
	out.Data.SetSource(string(eventSource))
}

// ProcessInChannel will be  called if Transport is disabled
func ProcessInChannel() {
	for { //nolint:gosimple
		select {
		case d := <-scConfig.EventInCh:
			if d.Type == channel.SUBSCRIBER {
				log.Printf("transport disabled,no action taken: request to create listener address %s was called,but transport is not enabled", d.Address)
			} else if d.Type == channel.PUBLISHER {
				log.Printf("no action taken: request to create sender for address %s was called,but transport is not enabled", d.Address)
			} else if d.Type == channel.EVENT && d.Status == channel.NEW {
				out := channel.DataChan{
					Address:        d.Address,
					Data:           d.Data,
					Status:         channel.SUCCESS,
					Type:           channel.EVENT,
					ProcessEventFn: d.ProcessEventFn,
				}
				if d.OnReceiveOverrideFn != nil {
					if err := d.OnReceiveOverrideFn(*d.Data, &out); err != nil {
						out.Status = channel.FAILED
					} else {
						out.Status = channel.SUCCESS
					}
				}
				scConfig.EventOutCh <- &out
			}
		case <-scConfig.CloseCh:
			return
		}
	}
}
