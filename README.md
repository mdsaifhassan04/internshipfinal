# Fenwick & Vane — Auction Backend

Node.js + Express API for the auction frontend: lot catalog, bidder
registration/login (ID + token, no password), and bid placement with
server-side validation. Data lives in memory and is mirrored to `db.json` on
every write, so state survives a restart.

## Setup

```bash
cd auction
npm install
npm start        # http://localhost:4000
```

## Auth model

There's no password — registering issues a bidder **login ID** (e.g.
`B-4821`) and a session **token**. The frontend stores the token and
sends it as `Authorization: Bearer <token>` on every bid. `/login`
re-issues a token for a bidder ID that already exists, in case the
frontend's stored token was cleared.

## Endpoints

| Method | Path                  | Auth | Body                | Description                          |
|--------|-----------------------|------|----------------------|---------------------------------------|
| POST   | `/api/auth/register`  | —    | `{ name }`           | Creates a bidder, returns `id`, `name`, `token` |
| POST   | `/api/auth/login`     | —    | `{ id }`             | Re-issues a token for an existing bidder ID |
| GET    | `/api/auth/me`        | ✓    | —                    | Returns the bidder for the current token |
| GET    | `/api/lots`           | —    | query: `search`, `category` | List/filter lots |
| GET    | `/api/lots/:id`       | —    | —                    | Single lot, with `minNextBid` and `msRemaining` |
| POST   | `/api/lots/:id/bids`  | ✓    | `{ amount }`         | Place a bid; rejects if closed or below the minimum |

All responses are JSON. Errors return `{ "error": "..." }` with a 4xx
status.

## Wiring up the existing frontend

The HTML frontend currently runs entirely client-side (localStorage
only). To connect it to this API: replace `loadLots`/`saveLots` with
`fetch('/api/lots')`, replace the local `register`/login logic with
calls to `/api/auth/register` and `/api/auth/login` (store the
returned `token` in place of the generated local ID), and replace the
bid-submit handler with `fetch('/api/lots/:id/bids', { headers: {
Authorization: 'Bearer ' + token } })`. Happy to make that wiring
change directly if you'd like.
