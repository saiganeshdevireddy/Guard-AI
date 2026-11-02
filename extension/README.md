# Guard AI Link Protection extension

This Manifest V3 extension checks ordinary HTTP and HTTPS link clicks by asking the local Guard AI backend at `http://127.0.0.1:8000/api/pipeline/event`. The content script sends the URL to the extension service worker; the service worker makes the fetch, so the request does not run in the website's JavaScript context.

The extension reads `action` and the English and Telugu text from the `Informer` step. It blocks `block` decisions with a full-screen red message, pauses `warn` decisions behind a yellow continue banner, and follows `allow` decisions. Both voice texts are displayed, and speech synthesis requests English (`en-IN`) followed by Telugu (`te-IN`). Telugu remains visible even if Chrome has no Telugu voice. When Guard AI cannot be reached, the extension displays **Guard AI backend not running** and offers Continue anyway or Go back.

## Manifest permissions

- `host_permissions`: `http://127.0.0.1:8000/*` allows the service worker to contact the local Guard AI API. The `http://*/*` and `https://*/*` host access allows the content script to run on ordinary web pages and inspect their clicked links. Chrome will display this broad site access when the extension is installed. No browser data is sent anywhere except the configured local Guard AI endpoint.
- `permissions`: empty. The extension does not request tabs, scripting, storage, or other privileged Chrome APIs.
- `content_scripts.matches`: page match patterns that inject `content.js` on HTTP and HTTPS pages. These are host match patterns, not additional named permissions.

## Load in Chrome

1. Start Guard AI locally and confirm `http://127.0.0.1:8000/api/health` responds.
2. Open `chrome://extensions` in Chrome and enable **Developer mode**.
3. Select **Load unpacked** and choose this `extension` folder.
4. Visit an ordinary website and click a link. `Safe` links continue, `Careful` links pause for a choice, and `Danger` links are blocked. The extension does not run on Chrome internal pages such as `chrome://`.

## Checks

From the repository root, run JavaScript syntax checks with Node.js:

```sh
node --check extension/background.js
node --check extension/content.js
```

The manifest can be parsed as JSON with:

```sh
node -e "JSON.parse(require('fs').readFileSync('extension/manifest.json', 'utf8'))"
```
