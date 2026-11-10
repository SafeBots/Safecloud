# Get Started: publish as an Author

An **Author** uploads content to the Safecloud network. The file is split into 256 KB chunks in your browser, each one content-addressed and optionally encrypted before anything leaves your machine. The Jet proxies the chunks to connected Drops; you get a root CID and an embed snippet.

---

## Option A: drag-drop dashboard (no code)

Open the author dashboard in any modern browser:

```
https://<your-jet>/Safecloud/player/author.html
```

1. **Drop a file** onto the upload zone, or click to browse. Any format — video, audio, PDF, whatever.
2. **Fill in metadata** (all optional): title, description, comma-separated tags.
3. **Choose encryption** — check the box if you want AES-256-GCM per-chunk encryption. A fresh 256-bit key is generated in the browser; it never leaves in one piece. The dashboard tells you what to do with the key after upload.
4. **Click Publish.** A progress bar shows chunking → encrypting (if on) → uploading.
5. **Copy the embed snippet.** The result panel shows the root CID and a ready-to-paste `<iframe>` tag.

That's it. No wallet required for a free upload. If the Jet charges for storage, the dashboard shows the estimated cost before you click Publish.

---

## Embedding in a static site

Paste the snippet from the result panel into any HTML page — a GitHub Pages site, a Netlify deploy, a WordPress post, anywhere:

```html
<iframe
  src="https://<jet>/Safecloud/player/embed.html?rootCid=bafy…&jetUrl=https%3A%2F%2F<jet>"
  sandbox="allow-scripts allow-same-origin"
  allow="autoplay; fullscreen; picture-in-picture"
  width="640" height="360"
  frameborder="0"
></iframe>
```

The player runs entirely inside the iframe, on the Jet's origin. Your static host never touches the content — it just holds the tag, exactly like a YouTube or Vimeo embed.

**Encrypted uploads** — the snippet will include a `#key=…` fragment and `&sf=1` in the URL:

```
…embed.html?rootCid=bafy…&jetUrl=…&sf=1#key=abc123…
```

The fragment is the viewer's half of the AES key. The Jet holds the other half and hands it to anyone who loads the player with that root CID. Together they reconstruct the full key and decrypt. Copy the full URL — hash and all — or the content won't play. If you lose the `#key=…` half, the content is unrecoverable.

**`sandbox` explained** — `allow-scripts` is required (the player is JavaScript). `allow-same-origin` is required for the Service Worker the player uses to stitch chunks into a stream and for the local capability cache. Without `allow-same-origin` the player loads but streaming breaks. Leave out `allow-top-navigation`, `allow-popups`, and `allow-forms` — the player doesn't need them and dropping them reduces the embedding page's attack surface.

---

## Option B: JavaScript library (developers)

For apps that need to trigger uploads programmatically, load `safecloud-upload.js` directly:

```html
<script src="https://<jet>/Safecloud/player/safecloud-upload.js"></script>
```

```js
const up = new SafecloudUpload({ jetUrl: 'https://jet.example.com' });

up.on('progress', ({ phase, pct }) => {
    console.log(phase, pct + '%');
    // phases: 'chunking', 'encrypting', 'uploading', 'done'
});

const { rootCid, embedUrl, urlFragment } = await up.upload(file, {
    title:       'My Podcast',
    description: 'Episode 42',
    tags:        ['music', 'podcast'],
    price:       '0',     // wei per chunk view ('0' = free)
    encrypt:     false    // true = AES-256-GCM split-key
});
```

`embedUrl` is the full iframe `src` including the `#key=…` fragment if the upload was encrypted. `urlFragment` is just the fragment, if you need to store it separately.

---

## Option C: Q.js API (Qbix plugin developers)

If you're building a Qbix plugin and want the full revenue-policy and grant machinery:

```js
Q.Safecloud.Client.store(file, { revenue: { policy: {
    payees:            [yourAddress],
    fractions:         [9000],       // 90% to you
    dynamicBps:        1000,         // 10% to infrastructure
    dynamicConstraint: ZERO32,       // any Jet/Drop may fill the dynamic slot
    targets:           []
} } });
```

The share panel gives you a link, an iframe snippet, and optionally a split-entropy passphrase. See the full Q.Safecloud.Client API in the README for grant types, teaser capabilities, and on-chain settlement.

---

## What you never have to trust

Your file is chunked and CID-hashed in the browser before any byte leaves. The Jet routes ciphertext — it can verify a chunk is uncorrupted (hash match) but cannot read it. If you enable encryption, the Jet holds only half the key. Revenue splits, if you configure them, are enforced by the OpenClaiming contract: either the full policy executes atomically or no one is paid.
