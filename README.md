# WINGOO Public 1.0 🕊️

This package is prepared for internet deployment.

## Stack
- Node.js + Express
- PostgreSQL
- Socket.IO
- JWT authentication
- bcrypt password hashing
- Helmet security headers
- Rate limiting
- Browser geolocation
- WINGOO pigeon delivery UI

## Deploy with Render

Render can deploy the Node service and managed Postgres from `render.yaml`.

1. Create a GitHub repository called `wingoo`.
2. Upload ALL files from this folder to that repository.
3. In Render, choose **New → Blueprint** and connect the GitHub repository.
4. Render reads `render.yaml` and creates:
   - `wingoo` web service
   - `wingoo-db` PostgreSQL database
5. Wait for the web service to become live.
6. Open the generated `onrender.com` URL.
7. Create your account.
8. Send the URL to your friend.

### Important
Render's free resources are intended for testing/hobby use and have limitations. The free Postgres database currently expires after 30 days, so don't treat the free database as permanent production storage.

## Local PostgreSQL

Set:
DATABASE_URL=postgresql://...
JWT_SECRET=...

Then:
npm install
npm start

Open http://localhost:3000

## What is now internet-ready
- Real accounts
- Real persistent users
- Real friend requests
- Real persistent messages
- Realtime Socket.IO delivery
- Protected location storage
- Server-side distance calculation
- Pigeon selection per message
- Health endpoint
- Production environment variables
- PostgreSQL instead of local SQLite

## Still needed before a serious public launch
- Google Maps Routes integration with a restricted API key
- Cloud image/voice storage
- Push notifications
- Account recovery
- Block/report/moderation
- Message pagination
- Location retention/deletion controls
- Privacy policy + Terms
- Production database plan/backups
- Custom domain
