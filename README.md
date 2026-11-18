# NLA — Network & Location Awareness
### Digital Privacy Intelligence Platform by Newtonix Tech House
> *"SEE YOUR DATA. KNOW ITS DESTINATION. CONTROL YOUR DIGITAL PRIVACY."*

## Architecture Overview
- **Frontend Dashboard**: React 19, TypeScript, Tailwind CSS v4, `d3-geo` + `world-atlas` interactive world map, `jspdf` binary PDF export.
- **Backend Services (`server.ts`)**: Node.js 22 + Express unified server providing:
  - Live DNS (`A`/`AAAA`/`CNAME`/`TXT`), TLS certificate, HTTP header, and IP GeoIP/ASN inspection (`POST /api/network/inspect`)
  - Live Web Origin & HTML/Script/Header scanner (`POST /api/apps/analyze-web`)
  - Android/iOS/Desktop Manifest & Permission analyzer (`POST /api/apps/analyze-manifest`)
  - Authorized HAR v1.2, Apple App Privacy Report (`.ndjson`), NLA JSON, and CSV capture parser (`POST /api/captures/parse`)
  - Cross-platform Node.js endpoint socket collector (`GET /api/agent/script` & `POST /api/agent/ingest`)
  - Server-side Gemini 4 Hydrogen (`@google/genai`) Privacy Agreement Analyzer (`POST /api/policies/analyze`) & NLA Intelligence Assistant (`POST /api/ai/chat`)
  - Real-time SSE monitoring stream (`GET /api/monitor/stream`)
  - Live OpenAPI JSON documentation (`GET /api/docs`)
- **Database & Auth**: Firebase Authentication (Google Sign-In) + Cloud Firestore (`firebase-blueprint.json`, `firestore.rules`) enforcing strict owner isolation, RBAC (`analyst`, `auditor`, `admin`), immutable audit logs, and SHA-256 forensic integrity hashes.

## Installation & Development
```bash
npm install
npm run dev       # Starts Express + Vite on port 3000
npm run lint      # Runs TypeScript type checking (tsc --noEmit)
npm run build     # Builds production frontend bundle into dist/
NODE_ENV=production npm start  # Runs Node.js production server on port 3000
```

## Security & Firestore Rules Auditing
```bash
npx eslint firestore.rules
```
See `security_spec.md` and `firestore.rules.test.ts` for data invariants and the Dirty Dozen adversarial verification payloads.

## Endpoint Collector Agent (Windows, Linux, macOS)
Download `nla-agent.mjs` from **Device Management** or `/api/agent/script` and run with explicit user authorization:
```bash
node nla-agent.mjs --endpoint https://YOUR_NLA_URL/api/agent/ingest --device-id my-workstation
```
