# Self-Signed Server Certificates for VSCP WebSocket Driver

This guide explains how to generate self-signed certificates for the VSCP WebSocket driver (`vscpl2drv-websocksrv`) to enable secure WebSocket connections (WSS).

## Prerequisites

- OpenSSL installed on your system
- Administrative access to create directories and set permissions

## Quick Start (One-Line Certificate Generation)

For a simple self-signed certificate with minimal configuration:

```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365 -nodes \
  -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost"
```

## Step-by-Step Certificate Generation

### 1. Generate Private Key

```bash
openssl genrsa -out key.pem 4096
```

### 2. Create Certificate Signing Request

```bash
openssl req -new -key key.pem -out cert.csr
```

When prompted, enter your organization details. For the **Common Name (CN)**, use your server's hostname or IP address (e.g., `localhost`, `192.168.1.100`).

### 3. Generate Self-Signed Certificate

```bash
openssl x509 -req -in cert.csr -signkey key.pem -out cert.pem -days 365
```

## Advanced: Certificate with Subject Alternative Names (SAN)

For certificates that work with multiple hostnames/IPs, create a configuration file:

### Create `server.conf`:

```ini
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = YourState
L = YourCity
O = YourOrganization
OU = IT Department
CN = localhost

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = *.localhost
DNS.3 = yourdomain.com
IP.1 = 127.0.0.1
IP.2 = ::1
IP.3 = 192.168.1.100
```

### Generate Certificate with SAN:

```bash
openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
  -keyout key.pem -out cert.pem \
  -config server.conf -extensions v3_req
```

## Certificate Installation

### 1. Create Certificate Directory

```bash
sudo mkdir -p /etc/vscp/certs
```

### 2. Move Certificates to Proper Location

```bash
sudo mv cert.pem /etc/vscp/certs/
sudo mv key.pem /etc/vscp/certs/
```

### 3. Set Proper Permissions

```bash
# Set ownership to vscp user
sudo chown vscp:vscp /etc/vscp/certs/*.pem

# Secure private key (read-only for owner)
sudo chmod 600 /etc/vscp/certs/key.pem

# Public certificate (readable by others)
sudo chmod 644 /etc/vscp/certs/cert.pem
```

## Configuration

### Update Driver Configuration

Modify your `websocketsrv.json` to enable TLS:

```json
{
    "debug": true,
    "write": false,
    "key-file": "/etc/vscp/vscp.key",
    "max-send-queue": 32000,
    "interface": "wss://localhost:8884",
    "path-users": "/path/to/users.json",
    "tls": {
        "ca": "/etc/vscp/certs/ca.pem",
        "cert": "/etc/vscp/certs/cert.pem",
        "key": "/etc/vscp/certs/key.pem"
    },
    "logging": {
        "file-enable-log": true,
        "file-log-level": "debug",
        "file-pattern": "[vcpl2drv-websocksrv %c] [%^%l%$] %v",
        "file-path": "/tmp/vscpl2drv-websocksrv.log",
        "file-max-size": 5242880,
        "file-max-files": 7,
        "console-enable-log": true,
        "console-log-level": "debug",
        "console-pattern": "[vcpl2drv-websocksrv %c] [%^%l%$] %v"
    },
    "enable-ws1": true,
    "enable-ws2": true,
    "enable-rest": true,
    "url-ws1": "ws1",
    "url-ws2": "ws2",
    "url-rest": "rest"
}
```

**Key Changes:**
- Changed `interface` from `ws://` to `wss://`
- Added `tls` configuration section with certificate paths

## Testing and Verification

### 1. Verify Certificate Details

```bash
openssl x509 -in /etc/vscp/certs/cert.pem -text -noout
```

### 2. Test TLS Connection

```bash
openssl s_client -connect localhost:8884 -servername localhost
```

### 3. Test WebSocket Connection

Using `wscat` (install with `npm install -g wscat`):

```bash
# Connect to WS1 endpoint (ignore self-signed certificate warnings)
wscat -c wss://localhost:8884/ws1 --no-check

# Connect to WS2 endpoint
wscat -c wss://localhost:8884/ws2 --no-check
```

## Security Considerations

### Self-Signed Certificate Limitations

- **Browser Warnings**: Browsers will display security warnings
- **No Chain of Trust**: Not validated by a trusted Certificate Authority
- **Manual Trust**: Clients must manually accept the certificate

### Production Recommendations

For production environments, consider:

1. **Let's Encrypt**: Free certificates from a trusted CA
   ```bash
   sudo apt install certbot
   sudo certbot certonly --standalone -d yourdomain.com
   ```

2. **Internal CA**: Set up an internal Certificate Authority for enterprise use

3. **Commercial Certificates**: Purchase from established CAs like DigiCert, GlobalSign, etc.

## Troubleshooting

### Common Issues

1. **Permission Denied**: Ensure vscp user has read access to certificates
2. **Wrong CN/SAN**: Certificate CN must match the hostname used in connections
3. **Expired Certificate**: Check certificate validity with `openssl x509 -in cert.pem -dates -noout`

### Debug Commands

```bash
# Check certificate expiration
openssl x509 -in /etc/vscp/certs/cert.pem -dates -noout

# Verify private key matches certificate
openssl x509 -noout -modulus -in /etc/vscp/certs/cert.pem | openssl md5
openssl rsa -noout -modulus -in /etc/vscp/certs/key.pem | openssl md5

# Test server response
curl -k -v https://localhost:8884/
```

## Certificate Renewal

Self-signed certificates should be renewed before expiration:

```bash
# Check days until expiration
openssl x509 -in /etc/vscp/certs/cert.pem -noout -dates

# Regenerate certificate (keeping the same private key)
openssl x509 -req -in cert.csr -signkey /etc/vscp/certs/key.pem -out new_cert.pem -days 365
```

---

This setup provides encrypted WebSocket connections for the VSCP driver while maintaining compatibility with the existing configuration structure.


[filename](./bottom-copyright.md ':include')