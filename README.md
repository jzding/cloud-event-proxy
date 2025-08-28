# cloud-event-proxy
  The cloud-event-proxy project provides a mechanism for events from the K8s infrastructure to be delivered to CNFs with low-latency.
  The initial event functionality focuses on the operation of the PTP synchronization protocol, but the mechanism can be extended for any infrastructure event that requires low-latency.
  The mechanism is an integral part of k8s/OCP RAN deployments where the PTP protocol is used to provide timing synchronization for the RAN software elements


 [![go-doc](https://godoc.org/github.com/redhat-cne/cloud-event-proxy?status.svg)](https://godoc.org/github.com/redhat-cne/cloud-event-proxy)
 [![Go Report Card](https://goreportcard.com/badge/github.com/redhat-cne/cloud-event-proxy)](https://goreportcard.com/report/github.com/redhat-cne/cloud-event-proxy)
 [![LICENSE](https://img.shields.io/github/license/redhat-cne/cloud-event-proxy.svg)](https://github.com/redhat-cne/cloud-event-proxy/blob/main/LICENSE)
## Contents
* [Transport Protocol](#event-transporter)
    * [HTTP Protocol](#http-protocol)
* [Authentication](#authentication)
    * [mTLS and OAuth Support](#mtls-and-oauth-support)
    * [Consumer Examples](#consumer-examples)
* [Publishers](#creating-publisher)
    * [JSON Example](#publisher-json-example)
    * [Go Example](#creating-publisher-golang-example)
* [Subscriptions](#creating-subscriptions)
    * [JSON Example](#subscription-json-example)
    * [GO Example](#creating-subscription-golang-example)
* [Rest API](#rest-api)
* [Cloud Native Events](#cloud-native-events)
  * [Event via sdk](#publisher-event-create-via-go-sdk)
  * [Event via rest api](#publisher-event-create-via-rest-api)
* [Metrics](#metrics)
* [Plugin](#plugin)

## Event Transporter
Cloud event proxy currently support one type of transport protocol
1. HTTP Protocol

### HTTP Protocol
#### Producer
CloudEvents HTTP Protocol will be enabled based on url in `transport-host`.
If HTTP is identified then the publisher will start a publisher rest service, which is accessible outside the container via k8s service name.
The Publisher service will have the ability to register consumer endpoints to publish events.

The transport URL is defined in the format of
```yaml
- "--transport-host=$(TRANSPORT_PROTOCAL)://$(TRANSPORT_SERVICE).$(TRANSPORT_NAMESPACE).svc.cluster.local:$(TRANSPORT_PORT)"
```

HTTP producer example

```yaml
 - name: cloud-event-sidecar
          image: quay.io/redhat-cne/cloud-event-proxy
          args:
            - "--metrics-addr=127.0.0.1:9091"
            - "--store-path=/store"
            - "--transport-host=http://ptp-event-publisher-service-NODE_NAME.openshift-ptp.svc.cluster.local:9043
            - "--api-port=9085"

```
The event producer uses a `pubsubstore` to store Subscriber information, including clientID, consumer service endpoint URI, resource ID etc. These are stored as one json file per registered subscriber. The `pubsubstore` needs to be mounted to a persistent volume in order to survive a pod reboot.

Example for configuring persistent storage

```yaml
     spec:
      nodeSelector:
        node-role.kubernetes.io/worker: ""
      serviceAccountName: hw-event-proxy-sa
      containers:
        - name: cloud-event-sidecar
          volumeMounts:
            - name: pubsubstore
              mountPath: /store
      volumes:
        - name: pubsubstore
          persistentVolumeClaim:
            claimName: cloud-event-proxy-store-storage-class-http-events
```

Example PersistentVolumeClaim
```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: cloud-event-proxy-store-storage-class-http-events
spec:
  storageClassName: storage-class-http-events
  resources:
    requests:
      storage: 10Mi
  accessModes:
  - ReadWriteOnce
```

#### Consumer
Consumer application will also set its own `transport-host`, which enabled cloud event proxy to run a service to listen to
incoming events posted by the publisher.
Consumer will also use `http-event-publishers` variable to request for registering  publisher endpoints for consuming events.

HTTP consumer example
```yaml
 - name: cloud-event-sidecar
          image: quay.io/redhat-cne/cloud-event-proxy
          args:
            - "--metrics-addr=127.0.0.1:9091"
            - "--store-path=/store"
            - "--transport-host=consumer-events-subscription-service.cloud-events.svc.cluster.local:9043"
            - "--http-event-publishers=ptp-event-publisher-service-NODE_NAME.openshift-ptp.svc.cluster.local:9043"
            - "--api-port=8089"
```

## Authentication

Cloud Event Proxy supports enterprise-grade authentication for secure event communication.

### mTLS and OAuth Support

The proxy provides comprehensive authentication mechanisms:

- **mTLS (Mutual TLS)**: Transport layer security with client certificate authentication
- **OAuth**: Application layer authentication using JWT tokens
- **OpenShift Integration**: Native support for OpenShift Service CA and OAuth server

For detailed configuration instructions, see:
- **[Authentication Implementation](AUTHENTICATION_IMPLEMENTATION.md)** - Complete implementation guide
- **[Consumer Examples](examples/consumer/README.md)** - Working consumer examples with authentication
- **[Manifest Examples](examples/manifests/README.md)** - Kubernetes deployment examples

### Consumer Examples

The repository includes fully functional consumer examples demonstrating:

- **Basic Consumer**: Simple event consumer without authentication
- **Authenticated Consumer**: Consumer with mTLS and OAuth authentication
- **OpenShift Integration**: Automated deployment with Service CA and OAuth server

Quick start:
```bash
# Deploy authenticated consumer with default cluster name (openshift.local)
make deploy-consumer

# Deploy with custom cluster name
export CLUSTER_NAME=your-cluster-name.com
make deploy-consumer

# Run authentication examples
cd examples/auth-examples && go run auth-examples.go
```

### Cluster Configuration

The authentication system uses dynamic cluster name configuration with **strict OAuth validation**:

- **Default**: `openshift.local` (consistent with ptp-operator)
- **Custom**: Set `CLUSTER_NAME` environment variable before deployment
- **OAuth URLs**: Automatically generated as `https://oauth-openshift.apps.${CLUSTER_NAME}`
- **Security**: OAuth tokens are validated against the exact configured issuer with no bypass mechanisms

This ensures OAuth issuer URLs match your actual OpenShift cluster configuration and prevents authentication bypass due to issuer mismatches.

#### Updating Cluster Name at Runtime

If you need to update the cluster name after deployment (e.g., when moving from test to production clusters):

**For PTP Operator (publisher side):**
```bash
# Update the operator deployment
oc set env deployment/ptp-operator -n openshift-ptp CLUSTER_NAME=your-cluster.example.com
oc rollout status deployment/ptp-operator -n openshift-ptp

# Verify authentication resources are updated
oc get configmap ptp-event-publisher-auth -n openshift-ptp -o jsonpath='{.data.config\.json}' | jq '.oauthIssuer'
```

**For Consumer (client side):**

**Method 1: Automated Redeployment (Recommended)**
```bash
# Set new cluster name and redeploy
export CLUSTER_NAME=your-cluster.example.com
make undeploy-consumer
make deploy-consumer

# Verify consumer is running with correct OAuth configuration
oc get configmap consumer-auth-config -n cloud-events -o jsonpath='{.data.config\.json}' | jq '.oauthIssuer'
oc logs deployment/cloud-consumer-deployment -n cloud-events --tail=10
```

**Method 2: Manual ConfigMap Update**
```bash
# Update consumer authentication configuration
CLUSTER_NAME=your-cluster.example.com
oc patch configmap consumer-auth-config -n cloud-events --type='json' -p="[
  {\"op\": \"replace\", \"path\": \"/data/config.json\", \"value\": \"{\\\"enableMTLS\\\": true, \\\"useServiceCA\\\": true, \\\"clientCertPath\\\": \\\"/etc/cloud-event-consumer/client-certs/tls.crt\\\", \\\"clientKeyPath\\\": \\\"/etc/cloud-event-consumer/client-certs/tls.key\\\", \\\"caCertPath\\\": \\\"/etc/cloud-event-consumer/ca-bundle/service-ca.crt\\\", \\\"enableOAuth\\\": true, \\\"useOpenShiftOAuth\\\": true, \\\"oauthIssuer\\\": \\\"https://oauth-openshift.apps.$CLUSTER_NAME\\\", \\\"oauthJWKSURL\\\": \\\"https://oauth-openshift.apps.$CLUSTER_NAME/oauth/jwks\\\", \\\"requiredScopes\\\": [\\\"user:info\\\"], \\\"requiredAudience\\\": \\\"openshift\\\", \\\"serviceAccountName\\\": \\\"consumer-sa\\\", \\\"serviceAccountToken\\\": \\\"/var/run/secrets/kubernetes.io/serviceaccount/token\\\"}\"}
]"

# Restart consumer to pick up changes
oc rollout restart deployment/cloud-consumer-deployment -n cloud-events
oc rollout status deployment/cloud-consumer-deployment -n cloud-events
```

**Verification Commands:**
```bash
# Check consumer OAuth configuration
oc get configmap consumer-auth-config -n cloud-events -o jsonpath='{.data.config\.json}' | jq '.oauthIssuer'

# Test OAuth server connectivity
CLUSTER_NAME=$(oc get configmap consumer-auth-config -n cloud-events -o jsonpath='{.data.config\.json}' | jq -r '.oauthIssuer' | sed 's|https://oauth-openshift.apps.||')
curl -k "https://oauth-openshift.apps.$CLUSTER_NAME/oauth/jwks"

# Check consumer logs for authentication status
oc logs deployment/cloud-consumer-deployment -n cloud-events | grep -E "OAuth|authentication|subscription"
```

### Recent Security Improvements

- **Fixed OAuth Security Vulnerability**: Implemented strict OAuth token validation to prevent unauthorized access
- **Enhanced Issuer Validation**: Token issuer must exactly match the configured OAuth issuer
- **Comprehensive Token Validation**: Expiration, audience, and signature verification
- **Clear Error Messages**: Authentication failures return specific error codes without exposing sensitive information

## Creating Publisher
### Publisher JSON Example
Create Publisher Resource: JSON request
```json
{
  "Resource": "/east-edge-10/vdu3/o-ran-sync/sync-group/sync-status/sync-state",
  "UriLocation": "http://localhost:9090/ack/event"
}
```

Create Publisher Resource: JSON response
```json
{
  "Id": "789be75d-7ac3-472e-bbbc-6d62878aad4a",
  "Resource": "/east-edge-10/vdu3/o-ran-sync/sync-group/sync-status/sync-state",
  "UriLocation": "http://localhost:9090/ack/event" ,
  "EndpointUri ": "http://localhost:9085/api/ocloudNotifications/v1/publishers/{publisherid}"
}
```

### Creating Publisher Golang Eexample

#### Creating publisher golang example with HTTP as transporter protocol
```go
package main
import (
	v1pubsub "github.com/redhat-cne/sdk-go/v1/pubsub"
	"github.com/redhat-cne/sdk-go/pkg/types"
)
func main(){
  //channel for the transport handler subscribed to get and set events
    eventInCh := make(chan *channel.DataChan, 10)
    pubSubInstance = v1pubsub.GetAPIInstance(".")
    endpointURL := &types.URI{URL: url.URL{Scheme: "http", Host: "localhost:9085", Path: fmt.Sprintf("%s%s", apiPath, "dummy")}}
    // create publisher
    pub, err := pubSubInstance.CreatePublisher(v1pubsub.NewPubSub(endpointURL, "test/test"))

}
```

## Creating Subscriptions
### Subscription JSON Example
Create Subscription Resource: JSON request
```json
{
  "Resource": "/east-edge-10/vdu3/o-ran-sync/sync-group/sync-status/sync-state",
  "UriLocation”: “http://localhost:9090/event"
}
```
Example Create Subscription Resource: JSON response
```json
{
  "Id": "789be75d-7ac3-472e-bbbc-6d62878aad4a",
  "Resource": "/east-edge-10/vdu3/o-ran-sync/sync-group/sync-status/sync-state",
  "UriLocation": "http://localhost:9090/ack/event",
  "EndpointUri": "http://localhost:8089/api/ocloudNotifications/v1/subscriptions/{subscriptionid}"
}
```

### Creating Subscription Golang Example

#### Creating subscription golang example with HTTP as transporter protocol
```go
package main
import (
	v1pubsub "github.com/redhat-cne/sdk-go/v1/pubsub"
	"github.com/redhat-cne/sdk-go/pkg/types"
)
func main(){
    //channel for the transport handler subscribed to get and set events
    eventInCh := make(chan *channel.DataChan, 10)

    pubSubInstance = v1pubsub.GetAPIInstance(".")
    endpointURL := &types.URI{URL: url.URL{Scheme: "http", Host: "localhost:8089", Path: fmt.Sprintf("%s%s", apiPath, "dummy")}}
    // create subscription
    pub, err := pubSubInstance.CreateSubscription(v1pubsub.NewPubSub(endpointURL, "test/test"))

}

```

## Rest-API

### Rest-API to create a Publisher and Subscription
Cloud-Event-Proxy container running with rest api plugin will be running a webservice and exposing following end points.
```html

POST /api/ocloudNotifications/v1/subscriptions
POST /api/ocloudNotifications/v1/publishers
GET /api/ocloudNotifications/v1/subscriptions
GET /api/ocloudNotifications/v1/publishers
GET /api/ocloudNotifications/v1/subscriptions/$subscriptionid
GET /api/ocloudNotifications/v1/publishers/$publisherid
GET /api/ocloudNotifications/v1/health
POST /api/ocloudNotifications/v1/log
POST /api/ocloudNotifications/v1/create/event

```

## Cloud Native Events

The following example shows a Cloud Native Events serialized as JSON:
(Following json should be validated with Cloud native events' event_spec.json schema)


```JSON
{
    "id": "5ce55d17-9234-4fee-a589-d0f10cb32b8e",
    "type": "event.synchronization-state-chang",
    "time": "2021-02-05T17:31:00Z",
    "data": {
    "version": "v1.0",
    "values": [{
        "resource": "/cluster/node/ptp",
        "dataType": "notification",
        "valueType": "enumeration",
        "value": "ACQUIRING-SYNC"
    }, {

        "resource": "/cluster/node/clock",
        "dataType": "metric",
        "valueType": "decimal64.3",
        "value": 100.3
    }]
    }
}
```
Event can be created via rest-api or calling sdk methods
To produce or consume an event, the producer and consumer should have created publisher and subscription objects
and should have access to the `id` of the publisher/subscription data objects.

```go
import (
   v1event "github.com/redhat-cne/sdk-go/v1/event"
   cneevent "github.com/redhat-cne/sdk-go/pkg/event"
   cneevent "github.com/redhat-cne/sdk-go/pkg/event/ptp"
)

// create an event
event := v1event.CloudNativeEvent()
event.SetID(pub.ID)
event.Type = string(ptp.PtpStateChange)
event.SetTime(types.Timestamp{Time: time.Now().UTC()}.Time)
event.SetDataContentType(cneevent.ApplicationJSON)
data := cneevent.Data{
Version: "v1",
Values: []cneevent.DataValue{
	    {
        Resource:  "/cluster/node/ptp",
        DataType:  cneevent.NOTIFICATION,
        ValueType: cneevent.ENUMERATION,
        Value:     cneevent.GNSS_ACQUIRING_SYNC,
        },
    },
}
data.SetVersion("v1")
event.SetData(data)

```
### Publisher event create via go-sdk
```go
cloudEvent, _ := v1event.CreateCloudEvents(event, pub)
//send event to transport (rest API does this action by default)
v1event.SendNewEventToDataChannel(eventInCh, pub.Resource, cloudEvent)

```

### Publisher event create via rest-api
```go

//POST /api/ocloudNotifications/v1/create/event
if pub,err:=pubSubInstance.GetPublisher(publisherID);err==nil {
    url = fmt.SPrintf("%s%s", server.HostPath, "create/event")
    restClient.PostEvent(pub.EndPointURI.String(), event)
}

```

## Metrics

### sdk-go metrics
Cloud native events sdk-go comes with following metrics collectors .
1. Number of events received  by the transport
2. Number of events published by the transport.
3. Number of connection resets.
4. Number of sender created
5. Number of receiver created

### rest-api metrics
Cloud native events rest API comes with following metrics collectors .
1. Number of events published by the rest api.
2. Number of active subscriptions.
3. Number of active publishers.

### cloud-event-proxy metrics
1. Number of events produced.
1. Number of events received.

[Metrics details ](docs/metrics.md)
## Plugin
[Plugin details](plugins/README.md)

## Supported PTP configurations
[Supported configurations](docs/configurations.md)
