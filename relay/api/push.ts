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
  if (typeof rec.device_token !== "string" || rec.device_token.length === 0) {
    return { ok: false, error: "Missing or empty 'device_token'" };
  }
  if (typeof rec.title !== "string" || rec.title.length === 0) {
    return { ok: false, error: "Missing or empty 'title'" };
  }
  return {
    ok: true,
    data: {
      device_token: rec.device_token,
      title: rec.title,
      body: typeof rec.body === "string" ? rec.body : undefined,
      category: typeof rec.category === "string" ? rec.category : undefined,
      severity: typeof rec.severity === "string" ? rec.severity : undefined,
    },
  };
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
  if (token !== relaySecret) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Parse and validate body
  let rawBody: unknown;
  try {
    rawBody = await request.json();
  } catch {
    return new Response(JSON.stringify({ error: "Invalid JSON body" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

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
    return new Response(
      JSON.stringify({
        error: "APNs request failed",
        detail: err instanceof Error ? err.message : String(err),
      }),
      { status: 502, headers: { "Content-Type": "application/json" } },
    );
  }

  if (!apnsResp.ok) {
    let apnsError: string;
    try {
      const errBody = await apnsResp.text();
      apnsError = errBody;
    } catch {
      apnsError = `HTTP ${apnsResp.status}`;
    }
    return new Response(
      JSON.stringify({
        error: "APNs rejected the push",
        status: apnsResp.status,
        detail: apnsError,
      }),
      { status: 502, headers: { "Content-Type": "application/json" } },
    );
  }

  return new Response(JSON.stringify({ sent: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}
