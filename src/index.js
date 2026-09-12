const GEMINI_RELAY_ORIGIN = "https://www.thenexus.kdns.fr";
const API_PREFIX = "/ai-prompt/api/gemini";
const ALLOWED_ORIGIN = "https://www.primecare.cloudns.org";

function corsHeaders(origin) {
  const headers = new Headers();

  if (origin === ALLOWED_ORIGIN) {
    headers.set("Access-Control-Allow-Origin", ALLOWED_ORIGIN);
  }

  headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  headers.set(
    "Access-Control-Allow-Headers",
    "Content-Type, X-Goog-Api-Key, Authorization"
  );
  headers.set("Access-Control-Expose-Headers", "Content-Type");

  return headers;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    /*
     * Only handle:
     *
     * /ai-prompt/api/gemini/v1beta/models/...
     */
    if (!url.pathname.startsWith(API_PREFIX + "/")) {
      return env.ASSETS.fetch(request);
    }

    /*
     * CORS preflight
     */
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(origin),
      });
    }

    /*
     * Only POST is allowed.
     */
    if (request.method !== "POST") {
      return new Response(
        JSON.stringify({
          error: {
            message: "Method Not Allowed",
          },
        }),
        {
          status: 405,
          headers: {
            "Content-Type": "application/json; charset=UTF-8",
            ...Object.fromEntries(corsHeaders(origin)),
          },
        }
      );
    }

    /*
     * Relay token must exist in Worker Secret.
     */
    if (!env.RELAY_TOKEN) {
      return new Response(
        JSON.stringify({
          error: {
            message: "RELAY_TOKEN is not configured",
          },
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json; charset=UTF-8",
            ...Object.fromEntries(corsHeaders(origin)),
          },
        }
      );
    }

    /*
     * /ai-prompt/api/gemini/
     *        ↓
     * /gemini-relay/
     */
    const relayPath = url.pathname.slice(API_PREFIX.length);

    const upstreamUrl =
      GEMINI_RELAY_ORIGIN +
      "/gemini-relay" +
      relayPath +
      url.search;

    /*
     * Copy the request headers, but deliberately remove
     * browser/API credentials.
     */
    const headers = new Headers(request.headers);

    headers.delete("host");
    headers.delete("content-length");

    /*
     * The browser must NOT be able to provide a Gemini API key
     * or a relay token.
     */
    headers.delete("x-goog-api-key");
    headers.delete("authorization");
    headers.delete("x-relay-token");

    /*
     * Worker injects the real relay authentication.
     */
    headers.set("X-Relay-Token", env.RELAY_TOKEN);

    try {
      const upstreamResponse = await fetch(upstreamUrl, {
        method: "POST",
        headers,
        body: request.body,
      });

      /*
       * Pass Gemini's response back to the browser.
       */
      const responseHeaders = new Headers(upstreamResponse.headers);

      responseHeaders.delete("content-length");

      const cors = corsHeaders(origin);
      for (const [key, value] of cors.entries()) {
        responseHeaders.set(key, value);
      }

      return new Response(upstreamResponse.body, {
        status: upstreamResponse.status,
        statusText: upstreamResponse.statusText,
        headers: responseHeaders,
      });
    } catch (error) {
      return new Response(
        JSON.stringify({
          error: {
            message: "Gemini relay request failed",
          },
        }),
        {
          status: 502,
          headers: {
            "Content-Type": "application/json; charset=UTF-8",
            ...Object.fromEntries(corsHeaders(origin)),
          },
        }
      );
    }
  },
};
