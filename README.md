# SkidChecker

SkidChecker is a local analysis web application for Minecraft mod `.jar` files. It decompiles submitted archives with FernFlower-compatible tooling and highlights suspicious patterns commonly associated with credential theft, loaders, and malicious utility mods.

## What it does

- Accepts mod jar uploads through a browser interface.
- Runs FernFlower-compatible decompilation against the uploaded archive.
- Scans the resulting source with rule-based detections and heuristics.
- Classifies the known payload below as `weedhack`:

```java
String var10 = "{\"username\":\"" + var3 + "\",\"uuid\":\"" + var5 + "\",\"accessToken\":\"" + var6 + "\",\"minecraftInfo\":\"46c19a54-e52d-42c1-9c7f-eda984c69042\"}";
```

## Requirements

- Node.js 20+
- Java installed and available on `PATH`
- A FernFlower-compatible jar available at one of these paths:
  - `FERNFLOWER_JAR` environment variable
  - `./vendor/fernflower.jar`
  - `./vendor/vineflower.jar`

Vineflower is also supported because it is a maintained FernFlower fork and exposes a compatible CLI for this workflow.

## Install

```powershell
npm install
```

Place the decompiler jar in `vendor/` or set `FERNFLOWER_JAR`.

## Run

```powershell
npm start
```

Open `http://localhost:3000`.

## Self-hosting

If you are deploying on your own web server, the simplest setup is to run the Node application behind Nginx, Caddy, or another reverse proxy. In that layout, the frontend and API are served from the same origin, so `public/config.js` can keep `apiBaseUrl` empty.

### Production environment

- Copy `.env.example` to your server environment configuration.
- Set `ALLOWED_ORIGINS` to your public site URL.
- Place `vineflower.jar` or `fernflower.jar` in `vendor/`, or set `FERNFLOWER_JAR` to an absolute path.

### Node deployment

Example process-manager start with PM2:

```bash
pm2 start ecosystem.config.cjs
pm2 save
```

Example reverse proxy target:

- Application listens on `0.0.0.0:3000` by default.
- Proxy public traffic from your domain to `http://127.0.0.1:3000`.

### Docker deployment

Build and run:

```bash
docker build -t skidchecker .
docker run -d \
  --name skidchecker \
  -p 3000:3000 \
  -e ALLOWED_ORIGINS=https://your-domain.example \
  skidchecker
```

If you prefer to keep the decompiler jar outside the image, mount it and set `FERNFLOWER_JAR` accordingly.

## GitHub Pages

GitHub Pages can host the frontend in `public/` and run the browser-mode scanner entirely on the client side.

- The Pages deployment workflow is defined in `.github/workflows/deploy-pages.yml`.
- If `public/config.js` leaves `apiBaseUrl` empty, the site runs in browser mode and scans jar contents locally in the browser.
- If you want the hosted Node/Java pipeline, set `window.SKIDCHECKER_CONFIG.apiBaseUrl` to the public URL of a separately hosted backend.
- A hosted backend must allow the GitHub Pages origin through the `ALLOWED_ORIGINS` environment variable.

Browser mode is fully static and works on GitHub Pages, but it does not run FernFlower on the server. Instead, it extracts readable content from the jar in the browser and applies the same family-oriented rule set.

Example frontend config:

```js
window.SKIDCHECKER_CONFIG = {
  apiBaseUrl: 'https://your-skidchecker-api.example.com'
};
```

Example backend CORS setting:

```powershell
$env:ALLOWED_ORIGINS = "https://your-user.github.io"
```

## Notes

- This is a local analysis tool, not a sandbox.
- Uploaded jars are not executed by the application. The pipeline only decompiles the archive and scans the resulting source text.
- Any decompiled source that references `method_1674()` is flagged as a critical session-token access indicator.
- The scanner is rule-based and intended for triage. It should be treated as a review aid rather than a definitive malware verdict.