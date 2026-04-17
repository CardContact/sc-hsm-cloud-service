# SmartCard-HSM Cloud Service

The SmartCard-HSM Cloud Service is a web-service exposing a REST API to access
SmartCard-HSMs connected via RAMOverHTTP to it.

Deploy this service as a sidecar to your own cloud service and get access to the device
without forwarding USB devices or remote PC/SC or PKCS#11 setups.

**WARNING** This is work-in-progress and currently nothing more than a Proof-of-Concept. There is no
further authentication at the REST-API, leaving keys fully exposed to any client connecting. To use this
in a production environment, you need to add TLS certificates and enable MTLS to authenticate a client
accessing the REST API.

## Connect a SmartCard-HSM

Use the [ram-client](https://www.pki-as-a-service.org/um/cloud-hsm/) to connect a SmartCard-HSM to the service:

```
ram-client -v -r "CardContact SmartCard-HSM [CCID Interface] (55992245609994) 02 00" http://localhost:8080/rt/hsm
```

As an alternative you can use the [OCF Client](https://www.openscdp.org/scriptingserver/remoteterminal.html) or the
"Connect to Portal" function in the [Key Manager of the Smart Card Shell](https://www.pki-as-a-service.org/km/key-manager/).

## OpenAPI

The OpenAPI definition can be found in api/sc-hsm-cloud-service.yaml.

## Using curl at the REST-API

Retrieve a list of HSMs, their key domains and keys:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/hsms
```

Retrieve a certain HSM:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/hsms/xxx.yyy.zzz
```

Retrieve a list of keys on a certain HSM:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/hsms/xxx.yyy.zzz/keys
```

Retrieve a certain key:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/hsms/xxx.yyy.zzz/keys/8877665544332211
```

Retrieve a list of all keys known at the service:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/keys
```

Retrieve a certain key:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/keys/8877665544332211
```

Retrieve a list of all known key domains:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/keydomains
```

Retrieve a certain key domain:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/keydomains/1122334455667788
```

Retrieve keys from a key domain:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/keydomains/1122334455667788/keys
```

Retrieve a certain key from a key domain:

```
curl -v --header "Accept: application/json"  http://localhost:8080/se/api/keydomains/1122334455667788/keys/8877665544332211
```

Perform a signing operation.

The input file must contain a hash and a signature algorithm.

```
{
	"hash": "0001020304050607000102030405060700010203040506070001020304050607",
	"algo": "ECDSA"
}
```

Send the request with POST to the `signhash` endpoint for the key.

```
curl -v --json @hashinput.json http://localhost:8080/se/api/keys/55C94D51BB88BE518061D4BD933F2520DEB79069/signhash
```

Supported algorithms are ECDSA for EC keys, RSA_PKCS1 and RSA_PSS for RSA keys.

## Tests

A test suite for the Smart Card Shell is contained in the `test` directory.

## Setting up a local development environment

To use the service locally, you need to install ant+ivy and run

    ant -Dunpack-fs=1 resolve
    
to retrieve the latest OpenSCDP `scriptingserver` and `scsh-mods`. See the `dockerfile` what is required
to bundle the components locally.

