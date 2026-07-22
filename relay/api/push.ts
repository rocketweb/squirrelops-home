/**
 * Vercel Edge Function: APNs Push Notification Relay
 *
 * Accepts POST requests from the SquirrelOps sensor and forwards push
 * notifications to Apple Push Notification service (APNs) using JWT-based
 * authentication.
 *
 * Required environment variables:
 *   RELAY_SECRET   - Bearer token the sensor must present
 *   APNS_KEY_ID    - Key ID from the Apple Developer portal (.p8 key)
 *   APNS_TEAM_ID   - Apple Developer Team ID
 *   APNS_KEY_BASE64 - Base64-encoded .p8 private key contents
 */

export const config = { runtime: "edge" };

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Import a PEM-encoded ES256 private key for signing. */
async function importAPNsKey(base64Key: string): Promise<CryptoKey> {
  const pem = atob(base64Key);
  // Strip PEM headers/footers and whitespace to get raw base64 DER
  const stripped = pem
    .replace(/-----BEGIN PRIVATE KEY-----/g, "")
    .replace(/-----END PRIVATE KEY-----/g, "")
    .replace(/\s/g, "");
  const der = Uint8Array.from(atob(stripped), (c) => c.charCodeAt(0));

  return crypto.subtle.importKey(
    "pkcs8",
    der.buffer,
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"],
  );
}

/** Base64url-encode a buffer or string. */
function base64url(input: ArrayBuffer | string): string {
  const bytes =
    typeof input === "string"
      ? new TextEncoder().encode(input)
      : new Uint8Array(input);
  let binary = "";
  for (const b of bytes) {
    binary += String.fromCharCode(b);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Build a short-lived JWT for APNs (ES256, 1-hour expiry). */
async function buildAPNsJWT(
  keyId: string,
  teamId: string,
  privateKey: CryptoKey,
): Promise<string> {
  const header = base64url(JSON.stringify({ alg: "ES256", kid: keyId }));
  const now = Math.floor(Date.now() / 1000);
  const claims = base64url(JSON.stringify({ iss: teamId, iat: now }));
  const signingInput = `${header}.${claims}`;
  const signature = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    privateKey,
    new TextEncoder().encode(signingInput),
  );

  // WebCrypto returns the signature in IEEE P1363 format (r || s, each 32 bytes)
  // which is what APNs expects.
  return `${signingInput}.${base64url(signature)}`;
}

// ---------------------------------------------------------------------------
// Request body schema
// ---------------------------------------------------------------------------

interface PushRequestBody {
  device_token: string;
  title: string;
  body?: string;
  category?: string;
  severity?: string;
}

function validateBody(
  obj: unknown,
): { ok: true; data: PushRequestBody } | { ok: false; error: string } {
  if (typeof obj !== "object" || obj === null) {
    return { ok: false, error: "Request body must be a JSON object" };
  }
  const rec = obj as Record<string, unknown>;
  // An APNs device token is hex. Validating it (rather than interpolating it
  // raw into the APNs URL path) prevents path/option injection into the
  // upstream request.
  if (
    typeof rec.device_token !== "string" ||
    !/^[0-9a-fA-F]{32,200}$/.test(rec.device_token)
  ) {
    return { ok: false, error: "Missing or invalid 'device_token'" };
  }
  if (typeof rec.title !== "string" || rec.title.length === 0) {
    return { ok: false, error: "Missing or empty 'title'" };
  }
  // Cap attacker-controlled text fields so a single push cannot be inflated.
  const cap = (s: string, n: number): string => (s.length > n ? s.slice(0, n) : s);
  return {
    ok: true,
    data: {
      device_token: rec.device_token,
      title: cap(rec.title, 256),
      body: typeof rec.body === "string" ? cap(rec.body, 1024) : undefined,
      category: typeof rec.category === "string" ? cap(rec.category, 64) : undefined,
      severity: typeof rec.severity === "string" ? cap(rec.severity, 32) : undefined,
    },
  };
}

/** Constant-time string comparison to avoid leaking the secret via timing. */
function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

// Reject bodies larger than this before parsing (defense in depth atop the
// platform limit). APNs alert payloads are well under 4 KB.
const MAX_BODY_BYTES = 8 * 1024;

async function readLimitedJSON(
  request: Request,
): Promise<
  | { ok: true; value: unknown }
  | { ok: false; status: number; error: string }
> {
  if (request.body === null) {
    return { ok: false, status: 400, error: "Invalid JSON body" };
  }
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        return { ok: false, status: 413, error: "Payload too large" };
      }
      chunks.push(value);
    }
    const body = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      body.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return {
      ok: true,
      value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)),
    };
  } catch {
    return { ok: false, status: 400, error: "Invalid JSON body" };
  } finally {
    reader.releaseLock();
  }
}

// ---------------------------------------------------------------------------
// Edge Function handler
// ---------------------------------------------------------------------------

export default async function handler(request: Request): Promise<Response> {
  // Only allow POST
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json", Allow: "POST" },
    });
  }

  // Authenticate via bearer token
  const relaySecret = process.env.RELAY_SECRET;
  if (!relaySecret) {
    return new Response(
      JSON.stringify({ error: "Server misconfigured: missing RELAY_SECRET" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  const authHeader = request.headers.get("Authorization") ?? "";
  const token = authHeader.startsWith("Bearer ")
    ? authHeader.slice(7)
    : "";
  if (!timingSafeEqual(token, relaySecret)) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Reject oversized bodies before reading them into memory.
  const contentLengthHeader = request.headers.get("Content-Length");
  const contentLength = Number(contentLengthHeader ?? "0");
  if (
    contentLengthHeader !== null &&
    (!/^\d+$/.test(contentLengthHeader) || !Number.isSafeInteger(contentLength))
  ) {
    return new Response(JSON.stringify({ error: "Invalid Content-Length" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }
  if (contentLength > MAX_BODY_BYTES) {
    return new Response(JSON.stringify({ error: "Payload too large" }), {
      status: 413,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Stream with an actual byte ceiling; Content-Length is optional and
  // attacker-controlled, so it is only an early rejection hint.
  const parsedBody = await readLimitedJSON(request);
  if (!parsedBody.ok) {
    return new Response(JSON.stringify({ error: parsedBody.error }), {
      status: parsedBody.status,
      headers: { "Content-Type": "application/json" },
    });
  }
  const rawBody = parsedBody.value;

  const validation = validateBody(rawBody);
  if (!validation.ok) {
    return new Response(JSON.stringify({ error: validation.error }), {
      status: 422,
      headers: { "Content-Type": "application/json" },
    });
  }
  const pushReq = validation.data;

  // Read APNs configuration from env
  const apnsKeyId = process.env.APNS_KEY_ID ?? "";
  const apnsTeamId = process.env.APNS_TEAM_ID ?? "";
  const apnsKeyBase64 = process.env.APNS_KEY_BASE64 ?? "";

  if (!apnsKeyId || !apnsTeamId || !apnsKeyBase64) {
    return new Response(
      JSON.stringify({ error: "Server misconfigured: missing APNs credentials" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  // Build APNs payload
  const apnsPayload = {
    aps: {
      alert: {
        title: pushReq.title,
        body: pushReq.body ?? "",
      },
      ...(pushReq.category ? { category: pushReq.category } : {}),
      "thread-id": pushReq.category ?? "SQUIRRELOPS",
    },
    severity: pushReq.severity ?? "low",
  };

  // Sign JWT and send to APNs
  let privateKey: CryptoKey;
  try {
    privateKey = await importAPNsKey(apnsKeyBase64);
  } catch {
    return new Response(
      JSON.stringify({ error: "Failed to import APNs signing key" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  let jwt: string;
  try {
    jwt = await buildAPNsJWT(apnsKeyId, apnsTeamId, privateKey);
  } catch {
    return new Response(
      JSON.stringify({ error: "Failed to build APNs JWT" }),
      { status: 500, headers: { "Content-Type": "application/json" } },
    );
  }

  const apnsUrl = `https://api.push.apple.com/3/device/${pushReq.device_token}`;

  let apnsResp: Response;
  try {
    apnsResp = await fetch(apnsUrl, {
      method: "POST",
      headers: {
        Authorization: `bearer ${jwt}`,
        "apns-topic": "com.squirrelops.home",
        "apns-push-type": "alert",
        "Content-Type": "application/json",
      },
      body: JSON.stringify(apnsPayload),
    });
  } catch (err) {
    // Log the detail server-side only; do not leak upstream internals.
    console.error("APNs request failed:", err instanceof Error ? err.message : String(err));
    return new Response(
      JSON.stringify({ error: "Upstream push failed" }),
      { status: 502, headers: { "Content-Type": "application/json" } },
    );
  }

  if (!apnsResp.ok) {
    let apnsError: string;
    try {
      apnsError = await apnsResp.text();
    } catch {
      apnsError = `HTTP ${apnsResp.status}`;
    }
    // Log the APNs reason (BadDeviceToken, etc.) server-side only; return a
    // generic error so the caller cannot use the relay as a token oracle.
    console.error("APNs rejected push:", apnsResp.status, apnsError);
    return new Response(
      JSON.stringify({ error: "Upstream push rejected" }),
      { status: 502, headers: { "Content-Type": "application/json" } },
    );
  }

  return new Response(JSON.stringify({ sent: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
