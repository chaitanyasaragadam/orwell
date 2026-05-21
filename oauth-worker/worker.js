/**
 * Cloudflare Worker — OAuth proxy + split-file GitHub user store
 *
 * Data layout in repo:
 *   data/users/_index.json          { login: status }  — fast status lookups
 *   data/users/<login>.json         full user record   — one file per user
 *
 * Endpoints:
 *   POST /exchange          — trade OAuth code for GitHub access token
 *   GET  /users/:login      — fetch full user record (caller must own the token)
 *   POST /users             — create user record on first login
 *
 * Worker secrets (wrangler secret put):
 *   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_ADMIN_TOKEN
 */

const ALLOWED_ORIGINS = [
  "https://chaitanyasaragadam.github.io",
  "http://localhost:3000",
];

const DB_OWNER = "chaitanyasaragadam";
const DB_REPO  = "orwell";
const DB_BASE  = "data/users";
const GH_API   = "https://api.github.com";

export default {
  async fetch(request, env) {
    const origin    = request.headers.get("Origin") || "";
    const isAllowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o));
    const cors = {
      "Access-Control-Allow-Origin":  isAllowed ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") return new Response(null, { headers: cors });

    const url = new URL(request.url);

    // ── POST /exchange ────────────────────────────────────────────────────────
    if (url.pathname === "/exchange" && request.method === "POST") {
      const { code } = await request.json();
      if (!code) return json({ error: "missing_code" }, 400, cors);

      const ghRes = await fetch("https://github.com/login/oauth/access_token", {
        method:  "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({
          client_id:     env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
        }),
      });
      const ghData = await ghRes.json();
      if (ghData.error) {
        return json({ error: ghData.error, description: ghData.error_description }, 400, cors);
      }
      return json({ access_token: ghData.access_token }, 200, cors);
    }

    // ── GET /users/:login ─────────────────────────────────────────────────────
    if (url.pathname.startsWith("/users/") && request.method === "GET") {
      const login = url.pathname.slice("/users/".length);
      if (!login) return json({ error: "missing_login" }, 400, cors);

      const caller = await verifyToken(request, env);
      if (!caller)         return json({ error: "unauthorized" }, 401, cors);
      if (caller !== login) return json({ error: "forbidden" }, 403, cors);

      const record = await readUserFile(env, login);
      if (!record) return json({ error: "not_found" }, 404, cors);
      return json(record, 200, cors);
    }

    // ── POST /users ───────────────────────────────────────────────────────────
    if (url.pathname === "/users" && request.method === "POST") {
      const caller = await verifyToken(request, env);
      if (!caller) return json({ error: "unauthorized" }, 401, cors);

      // Return existing record without overwriting
      const existing = await readUserFile(env, caller);
      if (existing) return json(existing, 200, cors);

      // Create new record
      const record = {
        login:     caller,
        status:    "pending",
        roles:     [],
        createdAt: new Date().toISOString(),
      };

      // Write individual file and update index in parallel
      await Promise.all([
        writeUserFile(env, caller, record),
        updateIndex(env, caller, "pending"),
      ]);

      return json(record, 201, cors);
    }

    return json({ error: "not_found" }, 404, cors);
  },
};

// ── Split-file DB helpers ─────────────────────────────────────────────────────

async function readUserFile(env, login) {
  const path = `${DB_BASE}/${login}.json`;
  const res  = await ghAdmin(env, "GET", `/repos/${DB_OWNER}/${DB_REPO}/contents/${path}`);
  if (res.status === 404) return null;
  const data = await res.json();
  return JSON.parse(atob(data.content.replaceAll("\n", "")));
}

async function writeUserFile(env, login, record) {
  const path    = `${DB_BASE}/${login}.json`;
  const content = btoa(JSON.stringify(record, null, 2));

  // Fetch existing SHA if the file already exists (needed for updates)
  const existing = await ghAdmin(env, "GET", `/repos/${DB_OWNER}/${DB_REPO}/contents/${path}`);
  const sha = existing.ok ? (await existing.json()).sha : undefined;

  const body = {
    message: `chore: upsert user ${login} [skip ci]`,
    content,
    ...(sha ? { sha } : {}),
  };
  await ghAdmin(env, "PUT", `/repos/${DB_OWNER}/${DB_REPO}/contents/${path}`, body);
}

async function updateIndex(env, login, status) {
  const path      = `${DB_BASE}/_index.json`;
  const res       = await ghAdmin(env, "GET", `/repos/${DB_OWNER}/${DB_REPO}/contents/${path}`);
  const existing  = res.ok ? await res.json() : null;
  const index     = existing ? JSON.parse(atob(existing.content.replaceAll("\n", ""))) : {};

  index[login] = status;

  await ghAdmin(env, "PUT", `/repos/${DB_OWNER}/${DB_REPO}/contents/${path}`, {
    message: `chore: update index for ${login} [skip ci]`,
    content: btoa(JSON.stringify(index, null, 2)),
    ...(existing ? { sha: existing.sha } : {}),
  });
}

function ghAdmin(env, method, path, body) {
  return fetch(`${GH_API}${path}`, {
    method,
    headers: {
      "Authorization": `Bearer ${env.GITHUB_ADMIN_TOKEN}`,
      "Accept":        "application/vnd.github+json",
      "Content-Type":  "application/json",
      "User-Agent":    "orwell-portal",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

async function verifyToken(request, _env) {
  const auth  = request.headers.get("Authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token) return null;

  const res = await fetch(`${GH_API}/user`, {
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept":        "application/vnd.github+json",
      "User-Agent":    "orwell-portal",
    },
  });
  if (!res.ok) return null;
  const data = await res.json();
  return data.login || null;
}

function json(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
