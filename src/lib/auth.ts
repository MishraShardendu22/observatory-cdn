// Authentication shared by the proxy (src/proxy.ts) and the API routes.
//
// Two ways in:
// 1. The browser session: /api/login sets `auth_token`, an HMAC-signed
//    "<username>.<expiry>" value. The key comes from AUTH_SECRET, or from
//    AUTH_USERNAME + AUTH_PASSWORD when AUTH_SECRET is not set. Sessions are
//    not stored on the server: changing AUTH_SECRET (or, without it, the
//    password) signs every browser out.
// 2. Scripts and tools: `Authorization: Bearer <CDN_API_TOKEN>`. Off unless
//    CDN_API_TOKEN is set (at least 32 characters).
//
// A request that changes something (any method but GET/HEAD/OPTIONS) and
// relies on the cookie must also come from this site's own pages: every
// *.mishrashardendu22.is-a.dev host is "same site" for the browser (is-a.dev
// is a public suffix), so SameSite=Lax alone would let a sibling subdomain
// send the cookie.
//
// Only Web Crypto is used, so this runs in the proxy and in route handlers.

export const SESSION_COOKIE = "auth_token";
export const SESSION_MAX_AGE_S = 60 * 60 * 24 * 7; // 7 days
const MIN_API_TOKEN_LENGTH = 32;
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

const encoder = new TextEncoder();

type RequestLike = {
  method: string;
  url: string;
  headers: { get(name: string): string | null };
  cookies: { get(name: string): { value: string } | undefined };
};

function sessionKeyMaterial(): string | null {
  const secret = process.env.AUTH_SECRET;
  if (secret) return `secret:${secret}`;
  const user = process.env.AUTH_USERNAME;
  const pass = process.env.AUTH_PASSWORD;
  if (!user || !pass) return null;
  return `password:${user}:${pass}`;
}

// One imported key per key material, so a request costs one HMAC, not a key
// import as well.
const keyCache = new Map<string, Promise<CryptoKey>>();
function hmacKey(material: string): Promise<CryptoKey> {
  let key = keyCache.get(material);
  if (!key) {
    key = crypto.subtle.importKey(
      "raw",
      encoder.encode(material),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"],
    );
    keyCache.clear(); // the env changes only on redeploy; keep one entry
    keyCache.set(material, key);
  }
  return key;
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromBase64Url(text: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) return null;
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const binary = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
    return Uint8Array.from(binary, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

// Compares two strings without leaking where they differ or their length:
// both are signed under a random per-call key, then the signatures are
// checked with crypto.subtle.verify.
export async function safeEqual(a: string, b: string): Promise<boolean> {
  const key = await crypto.subtle.importKey(
    "raw",
    crypto.getRandomValues(new Uint8Array(32)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(a));
  return crypto.subtle.verify("HMAC", key, sig, encoder.encode(b));
}

export async function createSessionToken(username: string): Promise<string> {
  const material = sessionKeyMaterial();
  if (!material) throw new Error("Server authentication is not configured");
  const expires = Date.now() + SESSION_MAX_AGE_S * 1000;
  const payload = `${toBase64Url(encoder.encode(username))}.${expires}`;
  const sig = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(material),
    encoder.encode(payload),
  );
  return `${payload}.${toBase64Url(new Uint8Array(sig))}`;
}

export async function verifySessionToken(
  token: string | undefined,
): Promise<boolean> {
  if (!token) return false;
  const material = sessionKeyMaterial();
  if (!material) return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  const [user, expires, sigText] = parts;
  if (!/^\d{1,16}$/.test(expires) || Number(expires) <= Date.now()) {
    return false;
  }
  const sig = fromBase64Url(sigText);
  if (!sig || sig.length !== 32) return false;
  return crypto.subtle.verify(
    "HMAC",
    await hmacKey(material),
    sig,
    encoder.encode(`${user}.${expires}`),
  );
}

let warnedShortToken = false;
export async function verifyApiToken(
  authorization: string | null,
): Promise<boolean> {
  const configured = process.env.CDN_API_TOKEN;
  if (!configured) return false;
  if (configured.length < MIN_API_TOKEN_LENGTH) {
    if (!warnedShortToken) {
      warnedShortToken = true;
      console.warn(
        `CDN_API_TOKEN is ignored: it must be at least ${MIN_API_TOKEN_LENGTH} characters (openssl rand -base64 48).`,
      );
    }
    return false;
  }
  const match = authorization?.match(/^Bearer\s+(\S+)\s*$/i);
  if (!match) return false;
  return safeEqual(match[1], configured);
}

// True when a browser request comes from this site's own pages.
function isSameOrigin(request: RequestLike): boolean {
  const fetchSite = request.headers.get("sec-fetch-site");
  if (fetchSite) return fetchSite === "same-origin";
  const origin = request.headers.get("origin");
  if (!origin) return false;
  const host =
    request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  try {
    return new URL(origin).host === (host ?? new URL(request.url).host);
  } catch {
    return false;
  }
}

export async function isAuthenticated(request: RequestLike): Promise<boolean> {
  if (process.env.DISABLE_AUTH === "true") return true;
  if (await verifyApiToken(request.headers.get("authorization"))) return true;
  if (!(await verifySessionToken(request.cookies.get(SESSION_COOKIE)?.value))) {
    return false;
  }
  return (
    SAFE_METHODS.has(request.method.toUpperCase()) || isSameOrigin(request)
  );
}

// Login throttling: after 5 failed attempts from one address within 15
// minutes, further attempts get 429 until the window passes. The counts live
// in this server instance's memory (each Vercel instance counts on its own),
// which slows a password guesser down without any storage.
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_FAILURES = 5;
const loginFailures = new Map<string, { count: number; since: number }>();

export function clientAddress(request: RequestLike): string {
  const forwarded = request.headers.get("x-forwarded-for");
  return (
    forwarded?.split(",")[0]?.trim() ||
    request.headers.get("x-real-ip") ||
    "unknown"
  );
}

export function loginBlocked(address: string): boolean {
  const entry = loginFailures.get(address);
  if (!entry) return false;
  if (Date.now() - entry.since > LOGIN_WINDOW_MS) {
    loginFailures.delete(address);
    return false;
  }
  return entry.count >= LOGIN_MAX_FAILURES;
}

export function recordLoginFailure(address: string): void {
  const now = Date.now();
  const entry = loginFailures.get(address);
  if (!entry || now - entry.since > LOGIN_WINDOW_MS) {
    loginFailures.set(address, { count: 1, since: now });
  } else {
    entry.count += 1;
  }
  if (loginFailures.size > 10_000) {
    for (const [addr, e] of loginFailures) {
      if (now - e.since > LOGIN_WINDOW_MS) loginFailures.delete(addr);
    }
  }
}

export function clearLoginFailures(address: string): void {
  loginFailures.delete(address);
}
