/**
 * Cloudflare Worker — OAuth proxy + user record store
 *
 * Endpoints:
 *   POST /exchange          — trade OAuth code for GitHub access token
 *   GET  /users/:username   — fetch user record (requires valid GitHub token)
 *   POST /users             — create user record on first login (requires valid GitHub token)
 *
 * Secrets (set via wrangler secret put):
 *   GITHUB_CLIENT_ID, GITHUB_CLIENT_SECRET
 *
 * KV binding: USERS_KV
 */

const ALLOWED_ORIGINS = [
  "https://chaitanyasaragadam.github.io",
  "http://localhost:3000",
];

export default {
  async fetch(request, env) {
    const origin    = request.headers.get("Origin") || "";
    const isAllowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o));

    const corsHeaders = {
      "Access-Control-Allow-Origin":  isAllowed ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // ── POST /exchange ────────────────────────────────────────────────────────
    if (url.pathname === "/exchange" && request.method === "POST") {
      const { code } = await request.json();
      if (!code) return json({ error: "missing_code" }, 400, corsHeaders);

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
      if (ghData.error) {
        return json({ error: ghData.error, description: ghData.error_description }, 400, corsHeaders);
      }
      return json({ access_token: ghData.access_token }, 200, corsHeaders);
    }

    // ── GET /users/:username ──────────────────────────────────────────────────
    if (url.pathname.startsWith("/users/") && request.method === "GET") {
      const username = url.pathname.split("/users/")[1];
      if (!username) return json({ error: "missing_username" }, 400, corsHeaders);

      // Verify the caller's GitHub token matches the requested username
      const caller = await getGitHubUser(request);
      if (!caller) return json({ error: "unauthorized" }, 401, corsHeaders);
      if (caller !== username) return json({ error: "forbidden" }, 403, corsHeaders);

      const record = await env.USERS_KV.get(username, { type: "json" });
      if (!record) return json({ error: "not_found" }, 404, corsHeaders);
      return json(record, 200, corsHeaders);
    }

    // ── POST /users ───────────────────────────────────────────────────────────
    if (url.pathname === "/users" && request.method === "POST") {
      const caller = await getGitHubUser(request);
      if (!caller) return json({ error: "unauthorized" }, 401, corsHeaders);

      // Don't overwrite an existing record
      const existing = await env.USERS_KV.get(caller, { type: "json" });
      if (existing) return json(existing, 200, corsHeaders);

      const record = {
        login:     caller,
        status:    "pending",
        roles:     [],
        createdAt: new Date().toISOString(),
      };
      await env.USERS_KV.put(caller, JSON.stringify(record));
      return json(record, 201, corsHeaders);
    }

    return json({ error: "not_found" }, 404, corsHeaders);
  },
};

// Verify GitHub token and return the login, or null if invalid
async function getGitHubUser(request) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.replace(/^Bearer\s+/i, "");
  if (!token) return null;

  const res = await fetch("https://api.github.com/user", {
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
