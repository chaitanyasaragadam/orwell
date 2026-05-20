/**
 * Cloudflare Worker — OAuth proxy + GitHub-backed user store
 *
 * User records live in data/users.json in the orwell repo.
 * The Worker reads/writes that file using GITHUB_ADMIN_TOKEN (admin PAT).
 * User identity is verified by checking their GitHub OAuth token.
 *
 * Endpoints:
 *   POST /exchange          — trade OAuth code for GitHub access token
 *   GET  /users/:username   — fetch user record (caller must own the token)
 *   POST /users             — create user record on first login
 *
 * Secrets (wrangler secret put):
 *   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET, GITHUB_ADMIN_TOKEN
 */

const ALLOWED_ORIGINS = [
  "https://chaitanyasaragadam.github.io",
  "http://localhost:3000",
];

const DB_OWNER  = "chaitanyasaragadam";
const DB_REPO   = "orwell";
const DB_PATH   = "data/users.json";
const GH_API    = "https://api.github.com";

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
        method: "POST",
        headers: { "Content-Type": "application/json", "Accept": "application/json" },
        body: JSON.stringify({
          client_id:     env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
        }),
      });
      const ghData = await ghRes.json();
      if (ghData.error) return json({ error: ghData.error, description: ghData.error_description }, 400, cors);
      return json({ access_token: ghData.access_token }, 200, cors);
    }

    // ── GET /users/:username ──────────────────────────────────────────────────
    if (url.pathname.startsWith("/users/") && request.method === "GET") {
      const username = url.pathname.split("/users/")[1];
      if (!username) return json({ error: "missing_username" }, 400, cors);

      const caller = await verifyToken(request);
      if (!caller)            return json({ error: "unauthorized" }, 401, cors);
      if (caller !== username) return json({ error: "forbidden" }, 403, cors);

      const { users } = await readDB(env);
      const record = users[username];
      if (!record) return json({ error: "not_found" }, 404, cors);
      return json(record, 200, cors);
    }

    // ── POST /users ───────────────────────────────────────────────────────────
    if (url.pathname === "/users" && request.method === "POST") {
      const caller = await verifyToken(request);
      if (!caller) return json({ error: "unauthorized" }, 401, cors);

      const { users, sha } = await readDB(env);

      // Return existing record without overwriting
      if (users[caller]) return json(users[caller], 200, cors);

      const record = {
        login:     caller,
        status:    "pending",
        roles:     [],
        createdAt: new Date().toISOString(),
      };
      users[caller] = record;
      await writeDB(env, users, sha);
      return json(record, 201, cors);
    }

    return json({ error: "not_found" }, 404, cors);
  },
};

// ── GitHub repo DB helpers ────────────────────────────────────────────────────

async function readDB(env) {
  const res = await ghAdmin(env, `GET /repos/${DB_OWNER}/${DB_REPO}/contents/${DB_PATH}`);
  if (res.status === 404) return { users: {}, sha: null };

  const data = await res.json();
  const content = JSON.parse(atob(data.content.replace(/\n/g, "")));
  return { users: content, sha: data.sha };
}

async function writeDB(env, users, sha) {
  const body = {
    message: `chore: update user records [skip ci]`,
    content: btoa(JSON.stringify(users, null, 2)),
  };
  if (sha) body.sha = sha;

  await ghAdmin(env, `PUT /repos/${DB_OWNER}/${DB_REPO}/contents/${DB_PATH}`, body);
}

function ghAdmin(env, endpoint, body) {
  const [method, path] = endpoint.split(" ");
  return fetch(`${GH_API}${path}`, {
    method,
    headers: {
      "Authorization": `Bearer ${env.GITHUB_ADMIN_TOKEN}`,
      "Accept": "application/vnd.github+json",
      "Content-Type": "application/json",
      "User-Agent": "orwell-portal",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

// Verify caller's GitHub token and return their login, or null
async function verifyToken(request) {
  const auth  = request.headers.get("Authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token) return null;

  const res = await fetch(`${GH_API}/user`, {
    headers: {
      "Authorization": `Bearer ${token}`,
      "Accept": "application/vnd.github+json",
      "User-Agent": "orwell-portal",
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
