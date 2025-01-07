# vscpl2drv-tcpipsrv

<img src="https://vscp.org/images/logo.png" width="100">


  * **Available for**: Linux, Windows
  * **Driver Linux**: libvscpl2drv-tcpipsrv.so
  * **Driver Windows**: vscpl2drv-tcpipsrv.dll

---

The tcp/ip driver act as a tcp/ip server for the [VSCP tcp/ip link protocol](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_over_tcp_ip). Users or IoT/m2m devices with different privileges and rights can connect to the exported interface and send/receive VSCP events.

The VSCP tcp/ip link protocol is described [here](https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_tcpiplink).

With the simple interface the driver uses ([described here](https://grodansparadis.github.io/vscp/#/level_ii_drivers)) it is also possible to use it with other software as a component.

## Install the driver on Linux
You can install the driver using the debian package with

> sudo apt install ./vscpl2drv-tcpipsrv_x.y.z.deb

the driver will be installed to /var/lib/vscp/drivers/level2

After installing the driver you need to add it to the vscpd.conf file (/etc/vscp/vscpd.conf). Se the *configuration* section below for how to do this.

You also need to set up a configuration file for the driver itself. If you don't need to dynamically edit the content of this file a good and safe location for it is in the */etc/vscp/* folder alongside the VSCP daemon configuration file.

If you need to do dynamic configuration a good place to put the file is in the */var/vscp/lib/vscp/vscpd/* folder or maybe a subfolder here. Make sure the _vscp_ user can read/write the location.

A sample configuration file is make available in */usr/share/vscpl2drv-tcpipsrv.so* after installation.

## Install the driver on Windows
tbd

## How to build the driver on Linux

- git clone --recurse-submodules -j8 https://github.com/grodansparadis/vscpl2drv-tcpipsrv.git
- sudo apt install pandoc           (comment: optional)
- sudo apt install build-essential
- sudo apt install cmake
- sudo apt install libexpat-dev
- sudo apt install libssl-dev
- sudo apt install libcurl4-openssl-dev
- sudo apt install rpm              (comment: only if you want to create install packages)
- cd vscpl2drv-tcpipsrv
- mkdir build
- cd build
- cmake ..
- make
- make install
- sudo cpack ..                     (comment: only if you want to create install packages)


Install of _pandoc_ is only needed if man pages needs to be rebuilt. This is normally already done and available in the repository.

## How to build the driver on Windows


### Install the vcpkg package manager

You need the vcpkg package manager on windows. Install it with

```bash
git clone https://github.com/microsoft/vcpkg.git
```

then go into the folder

```bash
cd vcpkg
```

Run the vcpkg bootstrapper command

```bash
bootstrap-vcpkg.bat
```

The process is described in detail [here](https://docs.microsoft.com/en-us/cpp/build/install-vcpkg?view=msvc-160&tabs=windows)

To [integrate with Visual Studio](https://docs.microsoft.com/en-us/cpp/build/integrate-vcpkg?view=msvc-160) run

```bash
vcpkg integrate install
```

Install the required libs

```bash
vcpkg install pthread:x64-windows
vcpkg install expat:x64-windows
vcpkg install openssl:x64-windows
```

Full usage is describe [here](https://docs.microsoft.com/en-us/cpp/build/manage-libraries-with-vcpkg?view=msvc-160&tabs=windows)

### Get the source

You need to checkout the VSCP main repository code in addition to the driver repository. You do this with

```bash
  git clone https://github.com/grodansparadis/vscp.git
  cd vscp
  git checkout development
``` 

and the vscpl2drv-tcpipsrv code

```bash
git clone https://github.com/grodansparadis/vscpl2drv-tcpipsrv.git
```

If you check out both at the same directory level the *-DVSCP_PATH=path-vscp-repository* in next step is not needed.

### Build the driver

Build as usual but use

```bash
cd vscpl2drv-tcpipsrv
mkdir build
cd build
cmake .. -CMAKE_BUILD_TYPE=Release|Debug -DCMAKE_TOOLCHAIN_FILE=E:\src\vcpkg\scripts\buildsystems\vcpkg.cmake -DVSCP_PATH=path-vscp-repository
```

The **CMAKE_TOOLCHAIN_FILE** path may be different in your case

Note that *Release|Debug* should be either *Release* or *Debug*

The windows build files can now be found in the build folder and all needed files to run the project can  after build - be found in build/release or build/Debug depending on CMAKE_BUILD_TYPE setting.

Building and configuration is simplified with VS Code installed. Configure/build/run can be done (se lower toolbar). Using VS Code it ,ay be useful to add

```json
"cmake.configureSettings": {
   "CMAKE_BUILD_TYPE": "${buildType}"
}
``` 

to your settings.json file.

To build at the command prompt use

```bash
msbuild vscp-works-qt.sln
```

Note that you must have a *developer command prompt*

### Build deploy packages 

Install NSIS from [this site](https://sourceforge.net/projects/nsis/).

Run 

```bash
cpack ...
```
 
in the build folder.

---

## Configuration

### Linux

#### VSCP daemon driver config

The VSCP daemon configuration is (normally) located at */etc/vscp/vscpd.conf*. To use the libvscpl2drv-tcpipsrv.so driver there must be an entry in the level2 driver section of this file

```json
"drivers": {
    "level2": [
```

The format is

```json
{
  "enable" : true,
  "name" : "tcpip-srv",
  "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-tcpipsrv.so",
  "path-config" : "/etc/vscp/tcpipsrv.json",
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
    "clientid": "the-vscp-daemon tcpipsrv driver",
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
        "topic": "vscp/tcpipsrv/{{guid}}/#",
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
##### enable
Set enable to "true" if the driver should be loaded by the VSCP daemon.

##### name
This is the name of the driver. Used when referring to it in different interfaces.

##### path-driver
This is the path to the driver. If you install from a Debian package this will be */var/lib/vscp/drivers/level2/libvscpl2drv-tcpipsrv.so*.

##### path-config
This is the path to the driver configuration file (see below). This file determines the functionality of the driver. A good place for this file is in _/etc/vscp/tcpipsrv.json_ It should be readable only by the user the VSCP daemon is run under (normally _vscp_) as it holds credentials to log in to a remote VSCP tcp/ip link interface. Never make it writable at this location.

##### guid
All level II drivers must have a unique GUID. There is many ways to obtain this GUID, Read more [here](https://grodansparadis.gitbooks.io/the-vscp-specification/vscp_globally_unique_identifiers.html). The tool [vscp_eth_to_guid](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=think-before-guid) is a useful tool that is shipped with the VSCP daemon that will get you a unique GUID if you are working on a machine with an Ethernet interface.

##### mqtt
See the [VSCP configuration documentation](https://grodansparadis.github.io/vscp/#/configuring_the_vscp_daemon?id=config-mqtt) for info about this section. It is common for all drivers.


---


#### vscpl2drv-tcpipsrv driver config

On start up the configuration is read from the path set in the driver configuration of the VSCP daemon, usually */etc/vscp/conf-file-name* and values are set from this location. If the **write** parameter is set to "true" the above location is a bad choice as the VSCP daemon will not be able to write to it. A better location is */var/lib/vscp/drivername/configure.xml* or some other writable location.

The configuration file have the following format

```json
{
  "debug" : true,
  "write" : false,
  "key-file" : "/etc/vscp/vscp.key",
  "max-out-queue" : 32000,
  "max-in-queue" : 32000,
  "interface" : "9598",
  "encryption" : "aes256",
  "path-users" : "/home/akhe/development/VSCP/vscpl2drv-tcpipsrv/debug/users.json",
  "receive-sent-events" : true,
  "tls" : {
    "certificate" : "",
    "certificate-chain" : "",
    "verify-peer" : false,
    "ca-path" : "",
    "ca-file" : "",
    "verify-depth" : 9,
    "default-verify-paths" : true,
    "cipher-list" : "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256",
    "protocol-version" : 3,
    "short-trust" : false
  },
  "logging" : {
    "file-enable-log": true,
    "file-log-level" : "debug",
    "file-pattern" : "[vcpl2drv-tcpipsrv %c] [%^%l%$] %v",
    "file-path" : "/tmp/vscpl2drv-tcpipsrv.log",
    "file-max-size" : 5242880,
    "file-max-files" : 7,
    "console-enable-log": true,
    "console-log-level" : "debug",
    "console-pattern" : "[vcpl2drv-tcpipsrv %c] [%^%l%$] %v"
  },
  "filter" : {
    "in-filter" : "incoming filter on string form",
    "in-mask" : "incoming mask on string form",
    "out-filter" : "outgoing filter on string form",
    "out-mask" : "outgoing mask on string form"
  } 
}
```

A default configuration file is written to [/usr/share/vscp/drivers/level2/vscpl2drv-tcpipsrv](/usr/share/vscp/drivers/level2/vscpl2drv-tcpipsrv) when the driver is installed.

##### debug
Set debug to _true_ to get debug information written to the log file. This can be a valuable help if things does not behave as expected.

##### write
If write is true dynamic changes to the configuration file will be possible to save dynamically to disk. That is, settings you do at runtime can be saved and be persistent. The safest place for a configuration file is in the VSCP configuration folder */etc/vscp/* but for dynamic saves are not allowed if you don't run the VSCP daemon as root (which you should not). Next best place is to use the folder */var/lib/vscp/drivers/level2/configure.json*. 

If you never intend to change driver parameters during runtime consider moving the configuration file to the VSCP daemon configuration folder is a good choice.

##### key-file
Currently not used.

###### response-timeout
Response timeout in milliseconds. Connection will be restarted if this expires.

##### max-out-queue
Maximum number of events in the send queue.

##### max-in-queue
Maximum number of events in the input queue.

##### interface
Set the interface to listen on. Default is: *tcp://localhost:9598*. The interface is either secure (TLS) or insecure. It is not possible to define interfaces that accept connections of both types.

if "tcp:// part is omitted the content is treated as it was present.

If port is omitted, default 9598 is used.

For TLS/SSL use prefix "stcp://"

##### encryption
Response and commands from/to the tcp/ip link server can be encrypted using AES-128, AES-192 or AES-256. Set here as

"none|aes128|aes192|aes256"

**Default**: is no encryption.

##### path-users
The user database is separated from the configuration file for security reasons and should be stored in a folder that is only readable by the user of the host, usually the VSCP daemon.

The format for the user file is specified below.

##### receive-sent-events
If set to true events sent by the driver will be received by the driver itself. This is useful for debugging and testing and may be used to verify that events are sent correctly. If set to false sent events are not received by the driver. However the **CHKDATA** command will still show sent events in it's count. This behavior may be changed ion the future.

##### TLS/SSL
Settings for TLS (Transport Layer Security), SSL.  Not used at the moment.

As TLS/SSL is not supported yet (it will be) in this driver it is important to understand that if used in an open environment like the internet it is not secure. People listening on the traffic can see both data and username/password credentials. It is therefore important to use the driver in a controlled environment and as early as possible move the flow of events to a secure environment like MQTT with TLS activated. This is often not a problem in a local cable based environment but is definitely a problem using wireless transmission that lack encryption.

A solution is to use a SSL wrapper like [this one](https://github.com/cesanta/ssl_wrapper). 

##### ssl_certificate
Path to SSL certificate file. This option is only required when at least one of the listening_ports is SSL The file must be in PEM format, and it must have both private key and certificate, see for example ssl_cert.pem. If this option is set, then the webserver serves SSL connections on the port set up to listen on.

**Default**: /srv/vscp/certs/server.pem

##### ssl_certificate_chain
T.B.D.

##### ssl_verify_peer
Enable client's certificate verification by the server.

**Default**: false

##### ssl_ca_path
Name of a directory containing trusted CA certificates for peers. Each file in the directory must contain only a single CA certificate. The files must be named by the subject name’s hash and an extension of “.0”. If there is more than one certificate with the same subject name they should have extensions ".0", ".1", ".2" and so on respectively.

##### ssl_ca_file"
Path to a .pem file containing trusted certificates for peers. The file may contain more than one certificate.

##### ssl_verify_depth
Sets maximum depth of certificate chain. If client's certificate chain is longer than the depth set here connection is refused.

**Default**: 9

##### ssl_default_verify_paths
Loads default trusted certificates locations set at openssl compile time.

**Default**: true

##### ssl_cipher_list
List of ciphers to present to the client. Entries should be separated by colons, commas or spaces.

| Selection	| Description |
| ========= | =========== |
| ALL |	All available ciphers |
| ALL:!eNULL | All ciphers excluding NULL ciphers |
| AES128:!MD5 | AES 128 with digests other than MD5 |

See [this entry in OpenSSL documentation](https://www.openssl.org/docs/manmaster/apps/ciphers.html) for full list of options and additional examples.

**Default**: "DES-CBC3-SHA:AES128-SHA:AES128-GCM-SHA256",

##### ssl_protocol_version
Sets the minimal accepted version of SSL/TLS protocol according to the table:

| Selected protocols | setting |
| ------------------ | ------- |
| SSL2+SSL3+TLS1.0+TLS1.1+TLS1.2 | 0 |
| SSL3+TLS1.0+TLS1.1+TLS1.2 | 1 |
| TLS1.0+TLS1.1+TLS1.2 | 2 |
| TLS1.1+TLS1.2	| 3 |
| TLS1.2 | 4 |

**Default**: 4.

##### ssl_short_trust
Enables the use of short lived certificates. This will allow for the certificates and keys specified in ssl_certificate, ssl_ca_file and ssl_ca_path to be exchanged and reloaded while the server is running.

In an automated environment it is advised to first write the new pem file to a different filename and then to rename it to the configured pem file name to increase performance while swapping the certificate.

Disk IO performance can be improved when keeping the certificates and keys stored on a tmpfs (linux) on a system with very high throughput.

**Default**: false

### Logging
In this section is the log console and log file settings. Before the configuration file is read logging will be sent to the console. 

Modes for logging can be set as of below. In debug/trace mode the debug flag above defines how much info is logged.

#### Logging to console

##### console-enable-log :id=config-general-logging-console-enable-log
Enable logging to a console by setting to *true*.

##### console-log-level :id=config-general-logging-console-log-level
Log level for console log. Default is "info".

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

##### console-pattern :id=config-general-logging-console-pattern

Format for consol log.

#### Logging to file

##### file-enable
Enable logging to a file by setting to _true_.

##### file-log-level 
Log level for file log. Default is _"info"_.

| Level | Description |
| ----- | ----------- |
| "trace" | Everything is logged |
| "debug" | Everything except trace is logged |
| "info" | info and above is logged |
| "err" | Errors and above is logged |
| "critical" | Only critical messages are logged |
| "off" | No logging |

##### file-pattern :id=config-general-logging-file-pattern
Log file pattern as described [here](https://github.com/gabime/spdlog/wiki/3.-Custom-formatting).

##### file-path :id=config-general-logging-file-path
Set a writable path to a file that will get log information written to that file. This can be a valuable help if things does not behave as expected.

##### file-max-size :id=config-general-logging-file-max-size
Max size for log file. It will be rotated if over this size. Default is 5 Mb.

##### file-max-files :id=config-general-logging-file-max-files
Maximum number of log files to keep. Default is 7.

#### filter
Filter and mask is a way to select which events is received by the driver. A filter have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

**Default**: setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the [vscpd manual](http://grodansparadis.github.io/vscp/#/) for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

#### mask
Filter and mask is a way to select which events is received by the driver. A mask have the following format

> priority,vscpclass,vscptype,guid

All values can be give in decimal or hexadecimal (preceded number with '0x'). GUID is always given i hexadecimal (without preceded '0x').

The mask have a binary one ('1') in the but position of the filter that should have a specific value and zero ('0') for a don't care bit.

Default setting is

> 0,0,0,00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00

Read the vscpd manual for more information about how filter/masks work.

The default filter/mask pair means that all events are received by the driver.

 #### Format for user database

 The user database is separated from the driver configuration file due to security reasons. It should be places in a file that is only readable by the _vscp_ user, the user the VSCP daemon us run under. 
 
 A good location for the file is _/etc/vscp/users.json_  Set user and group to _vscp_ and rights to 0x700.

 The installation script install a sample user file to _/usr/share/vscpl2drv-tcpipsrv/_. This file can be used as a starting point for your own setup. It defines two users. _admin_ and _user_ both with password _secret_.

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

##### user
The login user name

##### password
Hash calculated over "user:password" stored as md5 hash on hexadecimal format. On a Linux system you can generate this hash for a given username/password with

```bash
echo -n user:password | md5sum
```

With the VSCP daemon is a script **vscp-mkpassword** installed that can be used to generate passwords.

##### rights
Rights for this user as a 32-bit rights number.

##### name
Full name for user.

 ##### events
 This is a list with events the user is allowed to send and/or receive. If empty all events can be sent and received by the users.

 ###### class
 VSCP class. Can be set to -1 to allow all classes.

 ###### type
 VSCP type. Can be set to -1 to allow all types. 

 ###### dir
 The direction the user is allowed to handle. Set to "rx" to allow only receive. Set to "tx" to allow only transmit. Set to "both" or empty to allow sending and receiving.

###### max-priority
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

### Windows
See information from Linux. The only difference is the disk location from where configuration data is fetched.


```

## Using the vscpl2drv-tcpipsrv driver

Use the libvscpl2drv-tcpipsrv when you need a VSCP tcp/ip link interface to MQTT. Events you write to the driver MQTT subscribed topics will be received over the open tcp/ip channels. And events sent using the tcp/ip interface will be published on the configured publish topics. The driver can publish and subscribe to multiple topics. 

The [libvscpl2drv-tcpiplink](https://github.com/grodansparadis/vscpl2drv-tcpiplink#using-the-vscpl2drv-tcpiplink-driver) go through subscribe/publish topic techniques.

### A simple test run

Add the following to the level II section of the VSCP daemon configuration file

``` json
{
  "enable" : true,
  "name" : "tcpip-srv",
  "path-driver" : "/var/lib/vscp/drivers/level2/libvscpl2drv-tcpipsrv.so",
  "path-config" : "/etc/vscp/tcpipsrv.json",
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
    "clientid": "the-vscp-daemon tcpipsrv driver",
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
        "topic": "vscp/tcpipsrv/{{guid}}/#",
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

Copy _/var/share/vscpl2drv-tcpipsrv/tcpipsrv.json_ and _/var/share/vscpl2drv-tcpipsrv/users.json_ to _/etc/vscp_

```bash
sudo cp /var/share/vscpl2drv-tcpipsrv/tcpipsrv.json /etc/vscp
sudo cp /var/share/vscpl2drv-tcpipsrv/users.json /etc/vscp
```

Restart the vscp daemon

```bash
sudo systemctl restart vscpd
```

Now you should be able to login to the tcp/op interface. Try

```
telnet localhost 9598
```

and issue the following command when the server responds with something like

```
Trying 127.0.0.1...
Connected to localhost.
Escape character is '^]'.
Welcome to the VSCP tcp/ip server [l2drv].
Version: 15.0.0-0
Copyright © 2000-2025 Ake Hedman, the VSCP Project, https://www.vscp.org
+OK - Success.
```

```bash
user admin
pass secret
```

If you get 

```
+OK - Success
```

you are successfully connected. You can issue 

```bash
help
```

for a list of commands. (They are all described in detail in the VSCP specification https://grodansparadis.github.io/vscp-doc-spec/#/./vscp_tcpiplink

Now send a VSCP test event to the published topics

```
send 0,20,3,,,,0:1:2:3:4:5:6:7:8:9:10:11:12:13:14:15,0,1,35
```

This is the (CLASS1.INFORMATION, Type=3, VSCP_TYPE_INFORMATION_ON)[https://grodansparadis.github.io/vscp-doc-spec/#/./class1.information?id=type3] event. The three databytes are index (_0_), zone (_1_) and subzone (_35_) an dthe GUID is set to _0:1:2:3:4:5:6:7:8:9:10:11:12:13:14:15_

The ",,,,"means default are used for date tiem and timestamp and object id, They will be set to current UTC time and a valid timestamp.

You can instead send

```
send 0,20,3,,,,-,0,1,35
```

in which case the interface GUID will be used.

Use **mosquittp_sub** for example to se the published events. Like this

```bash
mosquitto_sub -h test.mosquitto.org -p 1883 -t vscp/#
```

**note**

Install mosquitto pub/sub with 

```
sudo tp install mosquitto-clients
```

if you don't have them installed


**note**

To repeat a command in the VSCP tcp/ip link interface press

```bash
'+' + <ENTER>
```

To check if you have received any event use the

```
chkdata
```

command and to retrive the events use

```
retr n
```

where n is the number of events you want to retreive.

You can also go into a revive loop with

```
rcvloop
```

now all events wil be listed as soon as they arrive. Use

```
quitloop
```

to terminate the receive loop.

When you ar ready use

```
quit
```

to terminate the session.

### Communication between tcp/ip clients
The original vscp daemon had a built in tcp/ip interface that was always activated.Event sent on one interface was automatically and by default sent to all other open interfaces. This is not the case with the VSCP tcp/ip link interface driver. Events sent on one interface is not sent on any other interface by defaults. If you want to send events on multiple interfaces you must enable this functionality explicitly.

Everything you send on a tcp/ip interface is now transfered to the MQTT broker you have set up. This is a good thing as it makes it possible to use the VSCP daemon as a gateway to the VSCP network from other systems.The same is true for all events recived on the tcp/ip interface. They originate from one or more MQTT topics.

So the only thing you have to do to receive events from oither clients is for one subscriber topic and one publish topic to be the same. If for example both subscribe to the topic "test" and both publish to the topic "test" they will be able to communicate with each other.

But there is one problem with this and that is that the tcp/ip interface that sends the event will also receive it's own events. This is not always what you want. To avoid this you can use a special configuration flag "receive-sent-events" in your tcpipsrv.json configuration file. It has a default value that is true. That is sent event will also be reveived.  If you set this to false, events sent by the driver itself will not be received by the driver anymore. 

However the **CHKDATA** command will still show sent events in it's count. This behavior may be changed ion the future.

Receiving your own events can be good if one want to confirm taht they actually are sent and has been received by the broker. But there are MQTT protocol flags that can be used to certify this.

### Using the driver with other software
It is very easy to interface VSCP Level II drivers from other software. Full information is [here](https://grodansparadis.github.io/vscp/#/level_ii_drivers)


## Other sources with information

 * The VSCP site - https://www.vscp.org
 * The VSCP document site - https://docs.vscp.org/
 * VSCP discussions - https://github.com/grodansparadis/vscp/discussions