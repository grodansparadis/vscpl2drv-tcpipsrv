

![](./images/widgets.png)

A typical use of vscpl2drv-tcpipsrv is when you want to visualize data from a VSCP node. By using the websocket interface you can publish live data on a web page with ease and the lowest possible resource overhead. The data can come from nodes connected to the network in different ways. One common way to retrieve data is through the event flow on a MQTT server as the VSCP daemon can publish data this way. Events on the MQTT subscribed topics will be received over the open websocket channel and is ready for display. Events sent using the websocket interface will be published on the configured publish topics and the functionality can be used for command button interactions etc.

Connected nodes may use a websocket interface to interface the world. In this case the driver can be used as the middleware between the VSCP network and the websocket connected nodes. A host can use the websocket driver to connect to such a node in a secure way.

## Testing ws1 in a web browser

![](./images/ws1-web-client.png)

There is a sample web client for testing the ws1 protocol in a web browser. The client is available [here](https://github.com/grodansparadis/vscpl2drv-websocksrv/blob/main/test/test_ws1.html).

A demo server is also available for testing [here](wss://vscp1.vscp.org:8884). Note that this is a public server and that data sent here may be visible to others. Username and password for the demo server is _admin/secret_ and default key.

### C, Python, node.js sample clients

In the same folder you can also find C, Python and node.js sample clients for testing the ws1 protocol.

## Testing ws2 in a web browser

![](./images/ws2-web-client.png)

There is a sample web client for testing the ws2 protocol in a web browser. The client is available [here](https://github.com/grodansparadis/vscpl2drv-websocksrv/blob/main/test/test_ws2.html).

A demo server is also available for testing [here](wss://vscp1.vscp.org:8884). Note that this is a public server and that data sent here may be visible to others. Username and password for the demo server is _admin/secret_ and default key.

### C, Python, node.js sample clients 

In the same folder you can also find C, Python and node.js sample clients for testing the ws2 protocol.

## Make your own application that interface the level II driver

It is very easy to interface VSCP Level II drivers from other software. Full information about the interface is [here](https://grodansparadis.github.io/vscp/#/level_ii_drivers)

Easiest is of course to link to the driver shared library from your own application. You can also load the driver manually at runtime if you want to be able to load different drivers without recompiling your application. The interface header is available [here](https://github.com/grodansparadis/vscp/blob/master/src/vscp/common/level2drvdef.h)

For manual linking there is a simple test application that can be used to test the websocket driver (or all level II drivers). The application is available in the [testapp](https://github.com/grodansparadis/vscpl2drv-websocksrv/tree/main/testapp) of the project.

This driver have hard coded credentials and paths so you need to edit it before use. All of them are defined in the beginning of the file.

The `testapp` loads and finds the methods of the driver manually so it is a good example of how to interface level II drivers from your own software. It will send a VSCP event every second and print any received events to the console. It should work on all supported platforms.

## Setting up your own VSCP Daemon for testing on Linux

Download and install the VSCP Daemon if you don't have it already. See [here](https://grodansparadis.github.io/vscp/#/) for information on how to do this.

Add the following to the level II section of the VSCP daemon configuration file

``` json
{
  "enable" : true,
  "name" : "websocket-srv",
  "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-websocksrv.so",
  "path-config" : "/etc/vscp/websocksrv.json",
  "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:02:88:88:00:00:00:00:01",

  "mqtt": {
    "bind": "",
    "host": "test.mosquitto.org",
    "port": 1883,
    "mqtt-options": {
      "tcp-nodelay": true,
      "protocol-version": 311,
      "receive-maximum": 20,
      "send-maximum": 20,
      "ssl-ctx-with-defaults": 0,
      "tls-ocsp-required": 0,
      "tls-use-os-certs": 0
    },
    "user": "vscp",
    "password": "secret",
    "clientid": "the-vscp-daemon websocksrv driver",
    "publish-format": "json",
    "subscribe-format": "auto",
    "qos": 1,
    "bcleansession": false,
    "bretain": false,
    "keepalive": 60,
    "bjsonmeasurementblock": true,
    "reconnect": {
      "delay": 2,
      "delay-max": 10,
      "exponential-backoff": false
    },
    "tls": {
      "cafile": "",
      "capath": "",
      "certfile": "",
      "keyfile": "",
      "pwkeyfile": "",
      "no-hostname-checking": true,
      "cert-reqs": 0,
      "version": "",
      "ciphers": "",
      "psk": "",
      "psk-identity": ""
    },
    "will": {
      "topic": "vscp-daemon/{{srvguid}}/will",
      "qos": 1,
      "retain": true,
      "payload": "VSCP Daemon is down"
    },
    "subscribe" : [
      {
        "topic": "vscp/websocksrv/{{guid}}/#",
        "qos": 0,
        "v5-options": 0,
        "format": "auto"
      }
    ],
    "publish" : [
      {
        "topic": "vscp/{{guid}}/{{class}}/{{type}}/{{nodeid}}",
        "qos": 1,
        "retain": false,
        "format": "json"
      }
    ]
  }
}
```

Copy _/var/share/vscpl2drv-websocksrv/websocksrv.json_ and _/var/share/vscpl2drv-websocksrv/users.json_ to _/etc/vscp_

```bash
sudo cp /var/share/vscpl2drv-websocksrv/websocksrv.json /etc/vscp
sudo cp /var/share/vscpl2drv-websocksrv/users.json /etc/vscp
```

Restart the vscp daemon

```bash
sudo systemctl restart vscpd
```





[filename](./bottom-copyright.md ':include')