# Safecloud Plugin — LLM Coding Primer

Decentralized encrypted storage network. Browser clients encrypt locally, Jet servers route ciphertext, Drop nodes (browser tabs) store chunks in IndexedDB. Plaintext never leaves the client. HLS video streaming via service worker. Micropayments via ERC-20 tokens with EIP-712 signatures.

## 1. Four Node Types
```
Cloud  — browser client: encrypts, decrypts, manifests, HLS streaming
Jets   — Node.js routing server: chunk routing, grant verification, payment check
Drops  — browser tabs: IndexedDB ciphertext storage, Prolly tree inventory
Router — Jet-to-Jet: Hyperswarm discovery, weighted Drop selection, relay
```

## 2. Client API (Browser-Side)
```javascript
// Store (encrypt + upload)
var result = await Q.Safecloud.Client.store(
    { data: blob, name: 'photo.jpg', type: 'image/jpeg' },
    { chunkSize: 256 * 1024 }
);
// Returns: { manifest, rootKey }
// Pipeline: rootKey → encryptionRoot → subtreeKey → chunkKey[i]/IV[i]
//   → AES-256-GCM encrypt → CID → Merkle root → Jets.put

// Fetch (download + verify + decrypt)
var blob = await Q.Safecloud.Client.fetch(manifest, { rootKey: rootKey });
// Merkle-verifies every chunk before decrypting

// Grant (produce a subtree capability for a grantee)
var capability = await Q.Safecloud.Client.grant(manifest, rootKey, {
    ranges: [{ start: 0, end: 10 }],  // chunk ranges
    readLevel: 40,
    exp: Math.floor(Date.now() / 1000) + 86400  // 24h expiry
});
// OCP Role A grant — cryptographic proof of access rights

// Reshare (grant + send to another user)
await Q.Safecloud.Client.reshare(manifest, rootKey, {
    userId: recipientUserId,
    readLevel: 30
});

// HLS Video Streaming
await Q.Safecloud.Client.play(videoId, videoElement, {
    manifest: manifest,
    capability: capability,
    versions: ['720p', '1080p']
});
// Service worker intercepts fetch to safecloud-hls.local/{videoId}/...
// Produces synthetic HLS playlists, decrypts segments on-the-fly

await Q.Safecloud.Client.pause(videoId);
await Q.Safecloud.Client.stream(videoId, { version: '1080p' }); // switch quality

// Upload (thin wrapper over store)
await Q.Safecloud.Client.upload(fileInput.files[0]);

// Download (thin wrapper over fetch → blob URL)
await Q.Safecloud.Client.download(manifest, { rootKey: rootKey });
```

## 3. Drops API (Browser Storage Nodes)
```javascript
// Initialize a Drop (browser tab offering storage)
await Q.Safecloud.Drops.init({
    maxStorage: 500 * 1024 * 1024,  // 500 MB
    evmAddress: '0x...'              // for payment claims
});

// Store and retrieve chunks
await Q.Safecloud.Drops.put(cid, ciphertext);
var chunk = await Q.Safecloud.Drops.get(cid);

// Announce inventory changes to Jet (signed, RFC 8785 canonical JSON)
await Q.Safecloud.Drops.announce('put');  // diff since last announce

// Claim micropayments for stored chunks
await Q.Safecloud.Drops.claimPayments();

// Inventory structures
var bloom = await Q.Safecloud.Drops.getBloomFilter();   // fast membership test
var root = await Q.Safecloud.Drops.getProllyRoot();      // content-addressed tree root
```

## 4. Jets API (Routing Server)
```javascript
// Server-side: start Jet
Q.Safecloud.Jets.listen({ port: 8443 });

// Client-side: connect browser to Jet
await Q.Safecloud.Jets.connect({ url: 'wss://jet.example.com' });

// Put/Get through Jet (routes to Drops)
await Q.Safecloud.Jets.put(rootCid, chunks, { payments: paymentTokens });
var result = await Q.Safecloud.Jets.get(rootCid, { start: 0, end: 5 });
// Jet selects Drops via Router, fans out requests, attaches Merkle proofs

// Drop lifecycle (server-side)
Q.Safecloud.Jets.callDrop(drop, 'Safe/drop/put', { cid, chunk });
Q.Safecloud.Jets.selectDrops(cids, opts);  // delegates to Router
Q.Safecloud.Jets.verifySubtreeGrant(grant, rootCid, chunkIndex);  // OCP verification
Q.Safecloud.Jets.buildMerkleProofs(chunks, merkleRoot);
Q.Safecloud.Jets._checkPayerBalance(payer, token, amount, chainId);  // ERC-20 pre-screen
```

## 5. Router (Pluggable Routing Layer)
```javascript
// Replace before listen() for custom strategy:
Q.Safecloud.Router = require('./Router.Kademlia');
Q.Safecloud.Jets.listen(options);

// Public interface (called by Jets):
await Router.init(options);
var drop = await Router.selectForGet(cid, options);      // weighted: stake × reliability × storage
var drops = await Router.selectForPut(cids, options);
var result = await Router.relayGet(subtree, options);     // Jet-to-Jet relay fallback
Router.announce(rootCid, 'available');                     // broadcast to peer Jets
Router.gossipCoC(chainOfCustody);                         // flood over Hyperswarm Noise

// Lifecycle hooks (called by Jets):
Router.onDropRegistered(drop, prollyRoot);
Router.onDropAnnounce(drop, diff);
Router.onDropDisconnected(drop);

// Peer Jets
var peers = Router.peerJets();  // [{evmAddress, url, stake}]
```

## 6. Key Hierarchy
```
rootKey (32 bytes, random or derived from videoKey+version)
  ├── encryptionRoot (HKDF) → P-256 keypair (encryptionRootPublicKey in manifest)
  │     └── subtreeKey (HKDF per subtree)
  │           └── chunkKey[i] + chunkIV[i] (HKDF per chunk index)
  │                 → AES-256-GCM encrypt
  └── accessRoot (HKDF) → P-256 keypair (accessRootPublicKey in manifest)
        └── OCP Role A grants (sign subtree access proofs)
```

## 7. Manifest (Public, No Secrets)
```javascript
{
    v: 1,                              // manifest version
    rootCid: '...',                    // Merkle root of all chunk CIDs
    encryptionRootPublicKey: '...',    // P-256 (65 bytes, uncompressed)
    accessRootPublicKey: '...',        // P-256 (65 bytes, uncompressed)
    bindingProof: '...',               // proves both keys + rootCid share one rootKey
    chunkCount: 42,
    chunkSize: 262144,                 // 256 KB default
    size: 10485760,                    // original file size
    name: 'photo.jpg'
}
// Manifest is safe to share publicly — no secrets, no plaintext
// bindingProof prevents key substitution attacks
```

## 8. HLS Service Worker
```javascript
// Service worker at Safecloud/sw.js intercepts:
//   https://safecloud-hls.local/{videoId}/master.m3u8
//   https://safecloud-hls.local/{videoId}/{version}/playlist.m3u8
//   https://safecloud-hls.local/{videoId}/{version}/seg-{N}.ts

// Populated by _prefetchLoop via postMessage:
//   { type: 'Q.Safecloud.Client.register', videoId, manifest, capability, versions }
//   { type: 'Q.Safecloud.Client.segment', videoId, version, segIndex, ciphertext, tag, iv }
//   { type: 'Q.Safecloud.Client.seek', videoId, segIndex }
//   { type: 'Q.Safecloud.Client.setVersion', videoId, version, manifest }
//   { type: 'Q.Safecloud.Client.stop', videoId }

// Decrypts segments on-the-fly, serves to <video> element as standard HLS
```

## 9. Server-Side Verification (Node.js)
```javascript
// Manifest validation
Q.Safecloud.Client.validateManifest(manifest);  // → {ok, reason}

// Binding proof verification (encKey + accKey + rootCid belong to same rootKey)
await Q.Safecloud.Client.verifyBindingProof(manifest);  // → Boolean

// OCP grant verification
await Q.Safecloud.Client.verifyGrant(grant, rootCid, chunkIndex);  // → Boolean

// Drop announce signature verification (P-256 over RFC 8785 canonical JSON)
Q.Safecloud.Drops.verifyAnnounce(announcePayload, publicKey);  // → Boolean

// Challenge response verification (proof-of-storage)
Q.Safecloud.Drops.verifyChallengeResponse(requestedCid, chunk);  // → Boolean

// Slash threshold check (reputation)
Q.Safecloud.Drops.shouldSlash(drop, failureLog);  // → Boolean
```

## 10. Common Mistakes
| Wrong | Right |
|-------|-------|
| Storing rootKey on the server | rootKey stays client-side; server sees only manifest (no secrets) |
| Sending plaintext to Jets | Client encrypts before upload; Jets/Drops see only ciphertext |
| Skipping Merkle verification on fetch | Always verify — `Client.fetch` does this automatically |
| Hardcoding Jet URL | Use `Q.Safecloud.Jets.connect()` which handles reconnection |
| Ignoring bindingProof | Prevents key-substitution attacks; always include in manifest |
| Using `put` without payment tokens | Jets verify ERC-20 balance; include `payments` option |
| Not calling `Drops.announce()` after puts | Jets need inventory updates for routing; announce after batch puts |
| Serving sw.js without Service-Worker-Allowed header | HLS interception requires `Service-Worker-Allowed: /` header |
| Assuming Drops persist forever | Drops are browser tabs; data can disappear; redundancy via multiple Drops |