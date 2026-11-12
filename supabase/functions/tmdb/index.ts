// TMDB proxy: the read token stays server-side instead of shipping in the
// browser bundle. Only the read-only paths src/services/tmdb.ts uses pass.
// shortcut: open to signed-out visitors (login screen shows trending), so
// anyone can spend TMDB quota through it; add rate limiting if that happens.

const TOKEN = Deno.env.get("TMDB_READ_ACCESS_TOKEN");
const ALLOWED_PATH =
  /^\/(trending\/(all|movie|tv)\/(day|week)|(movie|tv)\/(popular|\d+)|search\/multi|genre\/(movie|tv)\/list|discover\/(movie|tv))$/;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, accept",
};

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });

  const url = new URL(req.url);
  const path = url.pathname.replace(/^.*?\/tmdb(?=\/)/, "");
  if (req.method !== "GET" || !ALLOWED_PATH.test(path)) {
    return Response.json({ status_message: "path not allowed" }, { status: 400, headers: CORS });
  }

  const upstream = await fetch(`https://api.themoviedb.org/3${path}${url.search}`, {
    headers: { Authorization: `Bearer ${TOKEN}`, Accept: "application/json" },
  });
  return new Response(upstream.body, {
    status: upstream.status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
});
