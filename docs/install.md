# Safecloud Jet — Installation Guide

A Jet is the server-side component of a Safecloud deployment. It coordinates
encrypted chunk storage, payment settlement, and peer-to-peer Drop networking.

Three installation paths are available:

| Path | Best for |
|------|----------|
| [Binary release](#binary-release) | Production servers, VPS, Raspberry Pi — zero Node.js dependency |
| [npm / Node.js](#npm--nodejs) | Developers, Qbix plugin operators |
| [Docker](#docker) | Containerised deployments, Kubernetes |

---

## Binary release

Standalone binaries are published for each tagged release on
[GitHub Releases](https://github.com/Qbix/safecloud/releases).

No Node.js, no npm, no build step required.

### Supported platforms

| Binary | OS | Architecture |
|--------|----|--------------|
| `safecloud-jet-linux-x64`        | Linux  | x86-64 |
| `safecloud-jet-linux-arm64`      | Linux  | ARM64 (Raspberry Pi 5, AWS Graviton) |
| `safecloud-jet-macos-x64`        | macOS  | Intel |
| `safecloud-jet-macos-arm64`      | macOS  | Apple Silicon (M1/M2/M3/M4) |
| `safecloud-jet-windows-x64.exe`  | Windows | x86-64 |

### Quick start (Linux x64)

```bash
# 1. Download the binary for your platform
curl -LO https://github.com/Qbix/safecloud/releases/latest/download/safecloud-jet-linux-x64
chmod +x safecloud-jet-linux-x64

# 2. Create a working directory
mkdir -p ~/safecloud-jet/local
cd ~/safecloud-jet

# 3. (Optional) Create a config file
cat > local/app.json <<'EOF'
{
    "Safecloud": {
        "storage": {
            "backend": "filesystem",
            "filesystem": {
                "storageDir": "/var/safecloud/chunks"
            }
        }
    },
    "Q": {
        "node": {
            "port": 8080
        }
    }
}
EOF
mkdir -p /var/safecloud/chunks

# 4. Start the Jet
./safecloud-jet-linux-x64
```

On first start the Jet generates a wallet, prints the address, and writes
the private key to `local/app.json`. **Back up that file immediately.**

### Verify build provenance

Every binary is signed with GitHub's OIDC-based provenance attestation and
recorded in GitHub's transparency log. Verify before running:

```bash
gh attestation verify safecloud-jet-linux-x64 \
    --repo Qbix/safecloud
```

### SHA-256 checksums

A `checksums.txt` file is published alongside each release. Verify:

```bash
sha256sum -c checksums.txt --ignore-missing
```

### CLI flags

```
safecloud-jet-linux-x64 [options]

Options:
  --config <path>   Path to app.json config file
                    (default: ./local/app.json or $SAFECLOUD_CONFIG)
  --port <n>        Listen port (overrides config, default 8080)
                    (also $SAFECLOUD_PORT)
```

### Running as a systemd service

```ini
# /etc/systemd/system/safecloud-jet.service
[Unit]
Description=Safecloud Jet
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=safecloud
WorkingDirectory=/opt/safecloud-jet
ExecStart=/opt/safecloud-jet/safecloud-jet-linux-x64
Restart=on-failure
RestartSec=5

# Harden the service
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=/opt/safecloud-jet/local /var/safecloud/chunks

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -r -s /usr/sbin/nologin safecloud
sudo mkdir -p /opt/safecloud-jet/local /var/safecloud/chunks
sudo chown -R safecloud: /opt/safecloud-jet /var/safecloud/chunks
sudo cp safecloud-jet-linux-x64 /opt/safecloud-jet/
sudo systemctl daemon-reload
sudo systemctl enable --now safecloud-jet
```

---

## npm / Node.js

Node.js 22 or later is required.

```bash
# 1. Clone or install the package
git clone https://github.com/Qbix/safecloud.git
cd safecloud
npm install --omit=dev

# 2. Create config (same app.json format as above)
mkdir -p local
cat > local/app.json <<'EOF'
{
    "Safecloud": {
        "storage": {
            "backend": "filesystem",
            "filesystem": { "storageDir": "./chunks" }
        }
    }
}
EOF

# 3. Start
node bin/jet.js

# Or via npm script
npm run jet
```

---

## Docker

```bash
# Pull and run (filesystem backend, port 8080)
docker run -d \
  --name safecloud-jet \
  -p 8080:8080 \
  -v /opt/safecloud-jet/local:/app/local \
  -v /var/safecloud/chunks:/var/safecloud/chunks \
  ghcr.io/qbix/safecloud-jet:latest
```

### Build from source

```bash
git clone https://github.com/Qbix/safecloud.git
cd safecloud
docker build -t safecloud-jet:local .
docker run -d \
  -p 8080:8080 \
  -v ./local:/app/local \
  -v ./chunks:/var/safecloud/chunks \
  safecloud-jet:local
```

### docker-compose example

```yaml
version: '3.8'
services:
  jet:
    image: ghcr.io/qbix/safecloud-jet:latest
    restart: unless-stopped
    ports:
      - "8080:8080"
    volumes:
      - ./local:/app/local         # contains app.json + generated wallet
      - chunks:/var/safecloud/chunks
    environment:
      SAFECLOUD_PORT: "8080"
    healthcheck:
      test: ["CMD", "node", "-e", "require('http').get('http://localhost:8080/Safecloud/health',r=>process.exit(r.statusCode===200?0:1)).on('error',()=>process.exit(1))"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  chunks:
```

---

## Configuration reference

Configuration is read from `local/app.json` (or the path given by `--config`).
All keys are optional; sensible defaults are used when omitted.

### Core settings

```json
{
    "Q": {
        "node": {
            "host": "0.0.0.0",
            "port": 8080,
            "https": false
        }
    },
    "Safecloud": {
        "jet": {
            "privateKey": null,
            "address":    null,
            "settleIntervalSec": 900
        },
        "safebux": {
            "address": null,
            "chainId": "eip155:56"
        },
        "requirePayment": false,
        "storage": {
            "backend": "filesystem",
            "filesystem": {
                "storageDir": "/var/safecloud/chunks"
            }
        }
    }
}
```

### Storage backends

See [storage-backends.md](storage-backends.md) for full documentation on all
supported backends (filesystem, S3, WebDAV, Arweave, Filecoin, rclone).

### HTTPS

```json
{
    "Q": {
        "node": {
            "https": {
                "key":  "/etc/letsencrypt/live/example.com/privkey.pem",
                "cert": "/etc/letsencrypt/live/example.com/fullchain.pem"
            }
        }
    }
}
```

### Wallet

On first start the Jet auto-generates an Ethereum wallet and saves the private
key to `local/app.json` (mode 600). To use an existing key:

```json
{
    "Safecloud": {
        "jet": {
            "privateKey": "0x<64-hex-chars>",
            "address":    "0x<40-hex-chars>"
        }
    }
}
```

**Never commit `local/app.json` to version control.**

---

## Health check

```bash
curl http://localhost:8080/Safecloud/health
# → {"ok":true,"drops":0,"chunks":0}
```

## Dashboard

```
http://localhost:8080/Safecloud/dashboard
```

A minimal operator dashboard showing connected Drops, chunk counts, and
settlement status.

---

## Upgrading

### Binary

Download the new binary from the releases page, verify the checksum and
provenance attestation, then replace the old binary and restart the service.
No data migration is needed — chunk storage and `local/app.json` are
unchanged between patch and minor releases.

### npm / Docker

```bash
git pull && npm install --omit=dev    # from source
docker pull ghcr.io/qbix/safecloud-jet:latest  # Docker
```

---

## Troubleshooting

**Port already in use**
```
Error: listen EADDRINUSE: address already in use :::8080
```
Change the port: `--port 9090` or set `SAFECLOUD_PORT=9090`.

**Cannot parse local/app.json**
The config file may contain unsupported JSONC syntax. Validate with:
```bash
node -e "JSON.parse(require('fs').readFileSync('local/app.json','utf8'))"
```

**Wallet not generated**
Ensure `local/` exists and is writable by the Jet process:
```bash
mkdir -p local && chmod 700 local
```

**"Users plugin not available"**
This message appears at startup in standalone mode — it is informational.
The Jet creates its own socket.io server and does not depend on the Qbix
Users plugin.
