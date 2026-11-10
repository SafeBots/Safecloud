# Building Safecloud from Source

This guide covers how to build and run Safecloud Jet in each of its three modes: as a Node.js process, as a standalone binary, and as a Qbix platform plugin.

---

## Quick start: Node.js

Node.js 22 or later is required.

```bash
git clone https://github.com/Qbix/safecloud.git
cd safecloud
npm install
mkdir -p local
node bin/jet.js
```

The Jet starts on port 8080. On first run it generates a wallet and writes the private key to `local/app.json`. Back that file up immediately.

---

## Standalone binary (Node SEA)

The release workflow in `.github/workflows/release.yml` handles this automatically for tagged releases. To build a binary locally:

**Prerequisites**
- Node.js 22+
- npm (for esbuild and postject)

```bash
# 1. Install all dev dependencies (includes esbuild and postject)
npm install

# 2. Bundle bin/jet.js and all its require()s into one CommonJS file
npm run build:bundle
# → produces bin/jet-bundle.cjs

# 3. Generate the SEA blob from the bundle
npm run build:sea
# → produces sea-prep.blob

# 4. Copy the Node binary and inject the blob
cp "$(which node)" ./safecloud-jet-local
npx postject ./safecloud-jet-local NODE_SEA_BLOB sea-prep.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
chmod +x ./safecloud-jet-local

# 5. Run it
./safecloud-jet-local
```

On macOS you must strip and re-sign the binary after injection:

```bash
codesign --remove-signature ./safecloud-jet-local
npx postject ./safecloud-jet-local NODE_SEA_BLOB sea-prep.blob \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
codesign --sign - ./safecloud-jet-local
```

### How it works

`bin/jet.js` is a self-contained entry point that does not depend on the full Qbix platform. It sets up a minimal Q shim (config, Express server, socket.io, event emitter) and intercepts `require('Q')` and `require('Q/*')` via `Module._load`. When the Jet loads and those requires are hit, the interceptor routes them to the vendored copies under `classes/Q/`. `esbuild` then bundles the whole thing — entry point, vendored classes, and npm dependencies — into a single CommonJS file that Node SEA embeds in the binary.

---

## Docker

```bash
# Build image
docker build -t safecloud-jet:local .

# Run
docker run -d \
  -p 8080:8080 \
  -v ./local:/app/local \
  -v ./chunks:/var/safecloud/chunks \
  safecloud-jet:local
```

See `docs/install.md` for docker-compose examples and a full configuration reference.

---

## As a Qbix plugin

Safecloud can run as a first-class Qbix Platform plugin instead of standalone. In this mode Qbix's own Q object is used, and the vendored `classes/Q/` files are ignored.

**Prerequisites**
- A working [Qbix Platform](https://github.com/Qbix/Platform) installation
- Qbix's `NODE_PATH` set to include its `classes/` directory

**Install the plugin**

```bash
cd /path/to/qbix/APP/plugins
git clone https://github.com/Qbix/safecloud.git Safecloud
cd /path/to/qbix
php Q install Safecloud
npm install --prefix plugins/Safecloud --omit=dev
```

**Wire up in app.json** (Qbix application config)

```json
{
    "Q": {
        "plugins": ["Safecloud"]
    }
}
```

**Start Qbix normally** — the platform calls `Jets.listen()` via its plugin lifecycle. Safecloud's `Jets.js` uses `Q.listen()`, `Q.require('Users')`, and `Q.Config.get(...)` from the real Qbix Q object.

### Why no conflict between plugin and standalone

When Qbix sets `NODE_PATH` to its `classes/` directory, `require('Q/Data')` resolves to Qbix's `Q/Data.js`. Safecloud's vendored copy at `classes/Q/Data.js` is never loaded because it is not on the resolution path — it lives inside the safecloud plugin directory, not in a `NODE_PATH` location. The two paths are strictly separate; whichever context you run in, the right files are used automatically.

---

## Running tests

```bash
# Unit tests (no server required)
npm test

# Integration tests (require a running Jet, see tests/README.md)
npm run test:integration
```

---

## Versioning and releases

Tag a commit `vX.Y.Z` and push — the GitHub Actions workflow builds binaries for all five targets, attests provenance, and publishes a GitHub Release automatically.

```bash
git tag v1.2.3
git push origin v1.2.3
```
