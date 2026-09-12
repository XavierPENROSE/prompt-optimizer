const GEMINI_RELAY_ORIGIN = "https://www.thenexus.kdns.fr";
const API_PREFIX = "/ai-prompt/api/gemini";
const GROQ_API_PREFIX = "/ai-prompt/api/groq";
const APP_PREFIX = "/ai-prompt";
const ALLOWED_ORIGIN = "https://www.primecare.cloudns.org";

const AUTH_COOKIE = "prompt_optimizer_auth";
const AUTH_MAX_AGE = 60 * 60 * 24 * 7; // 7 days

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

function htmlResponse(html, status = 200) {
  return new Response(html, {
    status,
    headers: {
      "Content-Type": "text/html; charset=UTF-8",
      "Cache-Control": "no-store",
    },
  });
}

function redirectResponse(url) {
  return new Response(null, {
    status: 302,
    headers: {
      Location: url,
      "Cache-Control": "no-store",
    },
  });
}

function parseCookies(request) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = {};

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");

    if (index === -1) {
      continue;
    }

    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[name] = value;
  }

  return cookies;
}

function bytesToBase64(bytes) {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function importAuthKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"]
  );
}

async function createAuthToken(secret) {
  const timestamp = Math.floor(Date.now() / 1000);

  const key = await importAuthKey(secret);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(String(timestamp))
  );

  return `${timestamp}.${bytesToBase64(new Uint8Array(signature))}`;
}

async function verifyAuthToken(token, secret) {
  if (!token || !secret) {
    return false;
  }

  const separator = token.indexOf(".");

  if (separator === -1) {
    return false;
  }

  const timestamp = token.slice(0, separator);
  const signatureBase64 = token.slice(separator + 1);

  const timestampNumber = Number(timestamp);

  if (!Number.isFinite(timestampNumber)) {
    return false;
  }

  const now = Math.floor(Date.now() / 1000);

  if (now - timestampNumber < 0) {
    return false;
  }

  if (now - timestampNumber > AUTH_MAX_AGE) {
    return false;
  }

  try {
    const key = await importAuthKey(secret);

    return await crypto.subtle.verify(
      "HMAC",
      key,
      base64ToBytes(signatureBase64),
      new TextEncoder().encode(timestamp)
    );
  } catch {
    return false;
  }
}

async function isAuthenticated(request, env) {
  if (!env.AUTH_SECRET) {
    return false;
  }

  const cookies = parseCookies(request);
  const token = cookies[AUTH_COOKIE];

  return verifyAuthToken(token, env.AUTH_SECRET);
}

function loginPage(error = "") {
  const errorHtml = error
    ? `<div class="error">${error}</div>`
    : "";

  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Prompt Optimizer 登录</title>
<style>
body {
  margin: 0;
  min-height: 100vh;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #f5f5f5;
  font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.box {
  width: min(360px, calc(100vw - 40px));
  padding: 32px;
  background: white;
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0,0,0,.08);
  box-sizing: border-box;
}
h1 {
  margin: 0 0 24px;
  font-size: 22px;
  text-align: center;
}
input {
  width: 100%;
  box-sizing: border-box;
  padding: 12px;
  border: 1px solid #ccc;
  border-radius: 6px;
  font-size: 16px;
}
button {
  width: 100%;
  margin-top: 16px;
  padding: 12px;
  border: 0;
  border-radius: 6px;
  background: #1677ff;
  color: white;
  font-size: 16px;
  cursor: pointer;
}
.error {
  margin-bottom: 16px;
  padding: 10px;
  background: #fff2f0;
  color: #d4380d;
  border-radius: 6px;
  font-size: 14px;
}
</style>
</head>
<body>
<div class="box">
  <h1>Prompt Optimizer</h1>
  ${errorHtml}
  <form method="POST" action="/ai-prompt/login">
    <input
      type="password"
      name="password"
      placeholder="访问密码"
      autocomplete="current-password"
      required
      autofocus
    >
    <button type="submit">登录</button>
  </form>
</div>
</body>
</html>`;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get("Origin");

    /*
     * Authentication configuration check.
     */
    if (!env.AUTH_PASSWORD || !env.AUTH_SECRET) {
      return new Response(
        JSON.stringify({
          error: {
            message: "Authentication is not configured",
          },
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json; charset=UTF-8",
          },
        }
      );
    }

    /*
     * Only handle the Prompt Optimizer path.
     * Everything else goes to static assets.
     */
    if (
      url.pathname !== APP_PREFIX &&
      url.pathname !== APP_PREFIX + "/" &&
      !url.pathname.startsWith(APP_PREFIX + "/")
    ) {
      return env.ASSETS.fetch(request);
    }

    /*
     * Login page.
     */
    if (url.pathname === APP_PREFIX || url.pathname === APP_PREFIX + "/") {
      if (await isAuthenticated(request, env)) {
        return env.ASSETS.fetch(request);
      }

      return htmlResponse(loginPage());
    }

    /*
     * Login submission.
     */
    if (
      url.pathname === APP_PREFIX + "/login" &&
      request.method === "POST"
    ) {
      try {
        const formData = await request.formData();
        const password = formData.get("password");

        if (
          typeof password !== "string" ||
          password !== env.AUTH_PASSWORD
        ) {
          return htmlResponse(loginPage("密码错误"), 401);
        }

        const token = await createAuthToken(env.AUTH_SECRET);

        return new Response(null, {
          status: 302,
          headers: {
            Location: APP_PREFIX + "/",
            "Set-Cookie":
              `${AUTH_COOKIE}=${token}; ` +
              `Path=${APP_PREFIX}; ` +
              `Max-Age=${AUTH_MAX_AGE}; ` +
              `HttpOnly; ` +
              `Secure; ` +
              `SameSite=Strict`,
            "Cache-Control": "no-store",
          },
        });
      } catch {
        return htmlResponse(loginPage("登录请求处理失败"), 400);
      }
    }

    /*
     * Logout.
     */
    if (
      url.pathname === APP_PREFIX + "/logout" &&
      request.method === "GET"
    ) {
      return redirectResponse(APP_PREFIX + "/");
    }

    /*
     * Gemini API.
     */
    if (url.pathname.startsWith(API_PREFIX + "/")) {

      /*
       * CORS preflight must be allowed.
       * The actual POST request is still authenticated below.
       */
      if (request.method === "OPTIONS") {
        return new Response(null, {
          status: 204,
          headers: corsHeaders(origin),
        });
      }

      /*
       * Require authentication for every actual API request.
       */
      if (!(await isAuthenticated(request, env))) {
        return new Response(
          JSON.stringify({
            error: {
              message: "Authentication required",
            },
          }),
          {
            status: 401,
            headers: {
              "Content-Type": "application/json; charset=UTF-8",
              ...Object.fromEntries(corsHeaders(origin)),
            },
          }
        );
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
    }
/*
 * Groq API.
 */
if (url.pathname.startsWith(GROQ_API_PREFIX + "/")) {

  /*
   * CORS preflight must be allowed.
   * The actual POST request is still authenticated below.
   */
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders(origin),
    });
  }

  /*
   * Require authentication for every actual API request.
   */
  if (!(await isAuthenticated(request, env))) {
    return new Response(
      JSON.stringify({
        error: {
          message: "Authentication required",
        },
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json; charset=UTF-8",
          ...Object.fromEntries(corsHeaders(origin)),
        },
      }
    );
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
   * /ai-prompt/api/groq/
   *        ↓
   * /groq-relay/
   */
  const relayPath = url.pathname.slice(GROQ_API_PREFIX.length);

  const upstreamUrl =
    GEMINI_RELAY_ORIGIN +
    "/groq-relay" +
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
   * The browser must NOT be able to provide an API key,
   * Authorization header, or relay token.
   */
  headers.delete("authorization");
  headers.delete("x-relay-token");
  headers.delete("x-api-key");

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
     * Pass Groq's response back to the browser.
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
          message: "Groq relay request failed",
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
}
    /*
     * Other files under /ai-prompt/ require authentication.
     */
    if (!(await isAuthenticated(request, env))) {
      return htmlResponse(loginPage());
    }

    return env.ASSETS.fetch(request);
  },
};
