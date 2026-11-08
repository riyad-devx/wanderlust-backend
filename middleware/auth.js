import "dotenv/config";
import { createRemoteJWKSet, jwtVerify } from "jose";

const AUTH_BASE_URL =
  process.env.BETTER_AUTH_URL ||
  process.env.CLIENT_URL;

if (!AUTH_BASE_URL) {
  throw new Error(
    "[auth] BETTER_AUTH_URL or CLIENT_URL is required"
  );
}

const JWKS_URL = new URL(
  `${AUTH_BASE_URL.replace(/\/+$/, "")}/api/auth/jwks`
);



// These must match the JWT plugin configuration in the Better Auth server.
const JWT_ISSUER = "wanderlust";
const JWT_AUDIENCE = "wanderlust-api";
const JWT_ALGORITHMS = ["EdDSA"];

// Shared secret for the service-to-service JWKS request. The Next.js proxy
// rejects /api/auth/jwks unless this header matches.
const JWKS_ACCESS_KEY = process.env.JWKS_ACCESS_KEY;

if (!JWKS_ACCESS_KEY) {
  console.warn(
    "[auth] JWKS_ACCESS_KEY is not set — the JWKS endpoint will reject requests",
  );
}

// Caches keys and rate-limits refreshes, so an unknown `kid` cannot be used to
// hammer the Better Auth JWKS endpoint.
const jwks = createRemoteJWKSet(JWKS_URL, {
  cacheMaxAge: 10 * 60 * 1000,
  cooldownDuration: 30 * 1000,
  timeoutDuration: 5 * 1000,
  ...(JWKS_ACCESS_KEY && {
    headers: { "x-jwks-key": JWKS_ACCESS_KEY },
  }),
});

console.log(
  `[auth] JWT verification ready (issuer=${JWT_ISSUER}, audience=${JWT_AUDIENCE}, jwks=${JWKS_URL.href})`,
);

function unauthorized(res) {
  res.set("WWW-Authenticate", 'Bearer realm="wanderlust-api"');
  return res.status(401).json({ error: "Unauthorized" });
}

function getBearerToken(req) {
  const header = req.headers.authorization;

  if (typeof header !== "string") return null;

  const [scheme, token, ...extra] = header.trim().split(/\s+/);

  if (scheme?.toLowerCase() !== "bearer" || !token || extra.length > 0) {
    return null;
  }

  return token;
}

/**
 * Verifies a Better Auth JWT and returns its claims.
 * Throws when the token is missing, malformed, expired, or signed by an
 * unexpected key/algorithm.
 */
export async function verifyAccessToken(token) {
  const { payload, protectedHeader } = await jwtVerify(token, jwks, {
    issuer: JWT_ISSUER,
    audience: JWT_AUDIENCE,
    algorithms: JWT_ALGORITHMS,
    requiredClaims: ["sub", "exp", "iat"],
    clockTolerance: 5,
  });

  if (typeof payload.sub !== "string" || payload.sub.length === 0) {
    throw new Error("JWT is missing a valid subject");
  }

  return { payload, protectedHeader };
}

/**
 * Reusable Express middleware for private routes.
 * On success it attaches `{ userId, email, name, sessionId }` to `req.auth`.
 */
export async function requireAuth(req, res, next) {
  const token = getBearerToken(req);

  if (!token) {
    console.warn(
      `[auth] rejected ${req.method} ${req.originalUrl}: missing or malformed bearer token`,
    );
    return unauthorized(res);
  }

  try {
    const { payload, protectedHeader } = await verifyAccessToken(token);

    req.auth = {
      userId: payload.sub,
      email: typeof payload.email === "string" ? payload.email : undefined,
      name: typeof payload.name === "string" ? payload.name : undefined,
      sessionId:
        typeof payload.sessionId === "string" ? payload.sessionId : undefined,
    };

    // Log safe claims only. Never log the raw token or the secret.
    console.log(
      `[auth] verified ${req.method} ${req.originalUrl}`,
      JSON.stringify({
        sub: req.auth.userId,
        email: req.auth.email,
        alg: protectedHeader.alg,
        kid: protectedHeader.kid,
        exp: payload.exp,
      }),
    );

    return next();
  } catch (error) {
    const reason =
      error?.code === "ERR_JWT_EXPIRED" ? "expired token" : "invalid token";

    console.warn(`[auth] rejected ${req.method} ${req.originalUrl}: ${reason}`);

    return unauthorized(res);
  }
}
