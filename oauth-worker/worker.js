/**
 * Cloudflare Worker — GitHub OAuth secret proxy
 *
 * This is the ONLY backend piece. It holds the client_secret so it never
 * appears in the static HTML. Deploy to Cloudflare Workers free tier.
 *
 * Set secrets via CLI (never commit them):
 *   wrangler secret put GITHUB_CLIENT_ID
 *   wrangler secret put GITHUB_CLIENT_SECRET
 */

const ALLOWED_ORIGINS = [
  "https://chaitanyasaragadam.github.io",
  "http://localhost:3000",   // local dev
];

export default {
  async fetch(request, env) {
    const origin    = request.headers.get("Origin") || "";
    const isAllowed = ALLOWED_ORIGINS.some(o => origin.startsWith(o));

    const corsHeaders = {
      "Access-Control-Allow-Origin":  isAllowed ? origin : ALLOWED_ORIGINS[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    const url = new URL(request.url);

    // POST /exchange — trade the OAuth code for an access token
    if (url.pathname === "/exchange" && request.method === "POST") {
      const { code } = await request.json();
      if (!code) return json({ error: "missing_code" }, 400, corsHeaders);

      const ghRes = await fetch("https://github.com/login/oauth/access_token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Accept":        "application/json",
        },
        body: JSON.stringify({
          client_id:     env.GITHUB_CLIENT_ID,
          client_secret: env.GITHUB_CLIENT_SECRET,
          code,
        }),
      });

      const ghData = await ghRes.json();
      if (ghData.error) {
        return json(
          { error: ghData.error, description: ghData.error_description },
          400,
          corsHeaders
        );
      }

      // Only return the token — never forward the secret
      return json({ access_token: ghData.access_token }, 200, corsHeaders);
    }

    return json({ error: "not_found" }, 404, corsHeaders);
  },
};

function json(body, status, headers) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}
