
A VSCP level II  driver can be used with all VSCP level II host applications like the VSCP daemon and VSCP Works. The interface is very simple and is easily implemented also by other programs.

# vscpl2drv-tcpipsrv driver config

On start up the configuration is read from the path set in the driver configuration of the VSCP daemon, usually */etc/vscp/conf-file-name* and values are set from this location. 

Normally you find the driver configuration file in one of these locations

| Platform | Standard configuration file path |
| -------- | ----------------------- |
| Linux    | /etc/vscpvscpl2drv-websocksrv.json    |
| Windows  | C:\users\<user>\local\vscp\vscpvscpl2drv-websocksrv.json |
| MacOS   | /etc/vscp/vscpvscpl2drv-websocksrv.json    |

but you can put it wherever you want as long as the application using the driver has read access to it.

If the **write** parameter is set to "true" the  application that use the driver **must** be able to write to it. If this feature is used the standard locations are not the best places to put the file as they often require elevated privileges to write to if placed there.

The configuration file have the following format

```json
{
    "debug" : true,
    "write" : false,
    "enable-ws1" : true,
    "enable-ws2" : true,
    "enable-rest" : true,
    "enable-static" : false,
    "url-ws1" : "/ws1",
    "url-ws2" : "/ws2",
    "url-rest" : "/rest",
    "web-root" : "/tmp/www",
    "key-file" : "/etc/vscp/vscp.key",
    "interface" : "ws://localhost:8884",
    "rx-filter" : "0,0,0,-,0,0,0,-",
    "max-client-queue-size" : 32000,
    
    "path-users" : "/home/akhe/development/VSCP/vscpl2drv-websocksrv/debug/users.json",
    "tls" : {
      "ca" : "/etc/vscp/certs/ca.pem",
      "cert" : "/etc/vscp/certs/cert.pem",
      "key" : "/etc/vscp/certs/key.pem"
    },
    "logging" : {
      "log-level" : "debug",
      "file-enable-log": true,
      "file-pattern" : "[vcpl2drv-websocksrv %c] [%^%l%$] %v",
      "file-path" : "/tmp/vscpl2drv-websocksrv.log",
      "file-max-size" : 5242880,
      "file-max-files" : 7,
      "console-enable-log": true,
      "console-pattern" : "[vcpl2drv-websocksrv %c] [%^%l%$] %v"
    }
}
```

A default configuration file is written to [/usr/share/vscp/drivers/level2/vscpl2drv-websocksrv](/usr/share/vscp/drivers/level2/vscpl2drv-websocksrv) when the driver is installed. The repository contains a sample configuration file that can be used as a starting point [here](https://github.com/grodansparadis/vscpl2drv-websocksrv/blob/main/debug/conf_standard.json).

## debug
Set debug to _true_ to get extra debug information written to the log file. This can be a valuable help if things does not behave as expected. This is only for extra debug information. Normal error and info messages are always logged according to the logging settings.

## write (currently not used)
If write is true dynamic changes to the configuration file will be possible to save dynamically to disk. That is, settings you do at runtime can be saved and be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but for dynamic saves are not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivers/level2/configure.json*. 

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder is a good choice.

## enable-ws1
Set to true to enable VSCP webSocket ws1 interface support.

## enable-ws2
Set to true to enable VSCP webSocket ws2 interface support.

## enable-static
Set to true to enable static web content serving. `web-root` holds the path to the folder with the static content.

## url-ws1
The URL part of the VSCP webSocket ws1 interface. Default is `/ws1`

## url-ws2
The URL part of the VSCP webSocket ws2 interface. Default is `/ws2`

## web-root
Path to the folder with static web content to be served if `enable-static` is set to true.  

## key-file
Pointer to a file that holds the private key for the communication. This is used to authenticate the server to connecting clients. The file should hold a HEX string that is at least 16 bytes long. A good way to generate such a key is to use the command line tool _openssl_ like this

```bash
openssl rand -hex 16 > /etc/vscp/vscp.key
``` 

The file can be longer then 16 bytes so it is useful for stronger encryption. The extra bytes will be ignored here.

## interface
Set the interface to listen on. Default is: *ws://localhost:8884*. The interface is either secure using prefix `wss` (TLS) or insecure using prefix `ws`. It is not possible to define interfaces that accept connections of both types.

if "ws:// part is omitted the content is treated as it was present.

If port is omitted, default 8884 is used.


## path-users
The user database is separated from the configuration file for security reasons and should be stored in a folder that is only readable by the user of the host software.

The format for the user file is specified [below](#user-file-format).

## max-client-queue-size
Maximum number of events in the client send queue. If the queue is full new events for the client are dropped.

## rx-filter
Set a default filter/mask for incoming events. The format is `priority,vscpclass,vscptype,GUID;priority-mask,vscpclass-mask,vscptype-mask,GUID-mask` where each field in the filter part (before the ';') can be a specific value. Values in the mask tells which bits in the filter that should be checked. A bit set to zero means "ignore". All bits set to one means "the value must be the same as in the first part". As an example the filter/mask

> 0,10,6,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:01;0,255,255,00:00:00:00:00:00:00:00:00:00:00:00:00:FF

means that all events with class 10 and type 6 and any GUID with last byte set to 1 will pass the filter.

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given in hexadecimal (without preceded '0x').

## TLS/SSL
Settings for TLS (Transport Layer Security), SSL.  

It is important to understand that if used in an open environment like the internet it is not secure. People listening on the traffic can see both data and username/password credentials. It is therefore important to use the driver in a controlled environment and as early as possible move the flow of events to a secure environment with TLS activated. This is often not a problem in a local cable based environment but is definitely a problem using wireless transmission that lack encryption.

### Certificates overview

Transport Layer Security (TLS), and its predecessor, Secure Sockets Layer (SSL), are cryptographic protocols that provide communications security over a computer network.

TLS provides two major benefits:

`traffic encryption`, which makes it impossible to sniff and look inside the traffic, 

and

`authentication`, which makes it possible to one side of the TLS connection to verify the identity of the other side.

Here we're talking about authentication. Authentication is implemented via certificates. A certificate has two parts - public and private. Talking in practical terms, three files are required to implement TLS authentication:

`TLS certificate`: This is a "public" part. For example, a TLS-enabled server sends it to the client during the TLS handshake

`TLS private key`: This is a "private" part

`TLS Certificate Authority (CA) file`: This is used for verification of the "public" certificate sent by the server.

The private key must be kept secret. The certificate and the CA file can be shared freely.

Normally you set the certificate and the private key on the server side. The CA file is used on the client side to verify the server certificate.



TLS certificates can be obtained from services like [Let's Encrypt](https://letsencrypt.org/). The other possibility is self-signed certificates, which are mainly used for development. You have a guid here to create self-signed certificates using OpenSSL [here](https://www.baeldung.com/openssl-self-signed-cert).

Normally, when a client makes a connection to a TLS-enabled server, the server sends its certificate to the client and the client verifies it using its own CA (Certificate Authority) file. This way the client authenticates the server.

In the most common situation, the client verifies the server, but the server does not verify the client. For example, browsers (clients) use a big CA file (or many CA files) to verify HTTPS servers.

Clients can also provide certificates during the TLS handshake, and the server can verify it using a CA file. When both client and server use certificates, and verify the other side using a CA file, it is called `two-way TLS`. In order to implement two-way TLS, now both client and server must have their own cert, key and ca specified.

So for two-way TLS both sides must have three files - cert, key and ca.

#### Server
  * ca.pem - file with trusted CA certificates to verify client certificates
  * server_cert.pem - server TLS certificate
  * server_key.pem - server TLS private key

#### Client
  * ca.pem - file with trusted CA certificates to verify server certificates
  * client_cert.pem - client TLS certificate (only for two-way TLS)
  * client_key.pem - client TLS private key (only for two-way TLS)  

#### ca
Path to a file containing trusted CA certificates for peers. Each file  must contain a single CA certificate. The file must be in PEM format. If this option is set, then the webserver requests a certificate from clients that connect and verifies that the certificate is signed by one of the CAs in the file.

#### cert
Path to SSL certificate file. This option is only required when  the listening_ports is SSL The file must be in PEM format.


#### key
Path to SSL private key file. This option is only required when the listening_ports is SSL The file must be in PEM format. This is **NOT** the key file used to authenticate the server to clients. That key is set in the _key-file_ parameter above.


## Logging
In this section is the log console and log file settings. Before the configuration file is read logging will be sent to the console. 

Modes for logging can be set as of below. In debug/trace mode the debug flag above defines how much info is logged.

### log-level :id=config-general-logging-log-level
Log level for log. Default is "info".

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

### Logging to console

#### console-enable-log :id=config-general-logging-console-enable-log
Enable logging to a console by setting to *true*.



#### console-pattern :id=config-general-logging-console-pattern

Format for consol log.

### Logging to file

#### file-enable
Enable logging to a file by setting to _true_.

#### file-log-level 
Log level for file log. Default is _"info"_.

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

#### file-pattern :id=config-general-logging-file-pattern
Log file pattern as described [here](https://github.com/gabime/spdlog/wiki/3.-Custom-formatting).

#### file-path :id=config-general-logging-file-path
Set a writable path to a file that will get log information written to that file. This can be a valuable help if things does not behave as expected.

#### file-max-size :id=config-general-logging-file-max-size
Max size for log file. It will be rotated if over this size. Default is 5 Mb.

#### file-max-files :id=config-general-logging-file-max-files
Maximum number of log files to keep. Default is 7.

## filter
Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

**Default**: setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

## mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

## Format for the user database

 The user database is separated from the driver configuration file due to security reasons. It should be places in a file that is only readable by the _vscp_ user, the user the VSCP daemon us run under. 
 
 A good location for the file is _/etc/vscp/users.json_  Set user and group to _vscp_ and rights to 0x700.

 The installation script install a sample user file to _/usr/share/vscpl2drv-websocksrv/_. This file can be used as a starting point for your own setup. It defines two users. _admin_ and _user_ both with password _secret_.

 The user configuration file is on JSON format and looks like this.

 ```json
 {
  "users" : [
    {
      "user" : "admin",
      "fullname" : "Full name",
      "note" : "note about user-item",
      "credentials"  : "hash over 'user:password'",
      "filter" : "outgoing filter",
      "rights" : "comma separated list of rights",
      "remotes" : "comma separated list of hosts. First char: '+' = allow '-' = deny",
      "events" : "comma separated list of events where each item is specified as [TX|RX|BOTH;vscp-class;vscp.type;priority]"
    }
  ]
}
```

Any number of users can be specified

### user
The login user name

### password
Hash calculated over "user:password" stored as md5 hash on hexadecimal format. On a Linux system you can generate this hash for a given username/password with

```bash
echo -n user:password | md5sum
```

With the VSCP daemon is a script **vscp-mkpassword** installed that can be used to generate passwords.

### rights
Rights for this user as a 32-bit rights number.

### name
Full name for user.

### events
This is a list with events the user is allowed to send and/or receive. If empty all events can be sent and received by the users.

 ### class
 VSCP class. Can be set to -1 to allow all classes.

 ### type
 VSCP type. Can be set to -1 to allow all types. 

 ### dir
 The direction the user is allowed to handle. Set to "rx" to allow only receive. Set to "tx" to allow only transmit. Set to "both" or empty to allow sending and receiving.

### max-priority
Max priority (0-7) this user can use for send events. Trying to send an event with a higher priority will replace the event value with the value set here. Note that 0 is the highest priority.

---

The _users.json_ file looks like this

```json
{
  "users" : [
    {
      "name" : "admin",
      "password" : "487636FDE3637C7C853AAC9EAF6FA062;357C71CA59F760C08C4125C444A22A91FD1FE1FB0E5628771A572BAF6F61B71F",
      "fullname" : "Miss. Super User",
      "rights" : "admin",
      "remotes" : [
        "+127.0.0.0/24",
        "+192.168.0.0/16"                
      ],
      "events" : "",
      "filter" : "",
      "mask" : "",
      "note" : "A normal user. username='admin' password='secret'"
    },
    {
      "name" : "user",
      "password" : "0839DD1BE692164847B601E6520CE23B;3E1B4D950F04EA3BFA2C43160B9D98ECC76B249F79A1062F041C526978591BA3",
      "fullname" : "Mr. Sample User",
      "rights" : "user",
      "remotes" : "",
      "events" : "",
      "filter" : "",
      "mask" : "",						
      "note" : "A normal user. username='user' password='secret'"
    }
  ]
}
```

## Windows
See information from Linux. The only difference is the disk location from where configuration data is fetched.

## VSCP daemon driver config

To use the libvscpl2drv-websocksrv.so driver with the VSCP daemon there must be an entry in the level2 driver section of its configuration file. The location for the file is different for different platforms as in this table

| Platform | Standard configuration file path |
| -------- | ----------------------- |
| Linux    | /etc/vscp/vscpd.json    |
| Windows  | C:\users\<user>\local\vscp\vscpd.json |
| MacOS   | /etc/vscp/vscpd.json    |

The entry in the level2 driver section should look like this

```json
"drivers": {
    "level2": [
```

The format is

```json
{
  "enable" : true,
  "name" : "websocket-srv",
  "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-websocksrv.so",
  "path-config" : "/etc/vscp/websocksrv.json",
  "guid" : "FF:FF:FF:FF:FF:FF:FF:F5:02:88:88:00:00:00:00:01",

  "mqtt": {
    "bind": "",
    "host": "test.mqtt.org",
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
### enable
Set enable to "true" if the driver should be loaded by the VSCP daemon.

### name
This is the name of the driver. Used when referring to it in different interfaces.

### path-driver
This is the path to the driver. If you install from a Debian package this will be */var/lib/vscp/drivers/level2/libvscpl2drv-websocksrv.so*.

### path-config
This is the path to the driver configuration file (see below). This file determines the functionality of the driver. A good place for this file is in _/etc/vscp/websocksrv.json_ It should be readable only by the user the VSCP daemon is run under (normally _vscp_) as it holds credentials to log in to a remote VSCP websocket interface. Never make it writable at this location.

### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html). The tool [vscp_eth_to_guid](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=think-before-guid) is a useful tool that is shipped with the VSCP daemon that will get you a unique GUID if you are working on a machine with an Ethernet interface.

### mqtt
See the [VSCP configuration documentation](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=config-mqtt) for info about this section. It is common for all drivers loaded by the VSCP daemon.

## VSCP Works driver config

In VSCP Works you add the driver in the connection dialog in the level II driver section. You need to set the path to the driver and the path to the configuration file as above.

Using the level II driver interface as a connection in this way make it possible to open both server and client connections to VSCP websocket interfaces (and others) for debugging and development.







[filename](./bottom-copyright.md ':include')