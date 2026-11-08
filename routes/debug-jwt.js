import express from "express";
import { verifyAccessToken } from "../middleware/auth.js";

/*
 * TEMPORARY DEVELOPMENT-ONLY ENDPOINT.
 * Remove this file (and its import/mount in index.js) before production.
 *
 * GET /debug/jwt
 * - Requires a valid Better Auth session cookie.
 * - Forwards only the cookie to Better Auth's GET /api/auth/token.
 * - Verifies the returned JWT against the public JWKS before returning it.
 * - Returns no secrets and no private keys.
 */

const AUTH_BASE_URL = (
  process.env.BETTER_AUTH_URL ?? process.env.BETTER_AUTH_URL
).replace(/\/+$/, "");

const TOKEN_URL = new URL(`${AUTH_BASE_URL}/api/auth/token`);

const router = express.Router();

router.get("/jwt", async (req, res) => {
  const cookie = req.headers.cookie;

  if (!cookie) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    const upstream = await fetch(TOKEN_URL, {
      method: "GET",
      headers: {
        accept: "application/json",
        cookie,
      },
      signal: AbortSignal.timeout(5_000),
    });

    if (upstream.status === 401 || upstream.status === 403) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    if (!upstream.ok) {
      console.error(
        `[debug-jwt] Better Auth token endpoint returned ${upstream.status}`,
      );
      return res.status(502).json({ error: "Could not generate JWT" });
    }

    const data = await upstream.json();

    if (typeof data?.token !== "string" || data.token.length === 0) {
      console.error("[debug-jwt] Better Auth returned no token");
      return res.status(502).json({ error: "Could not generate JWT" });
    }

    // Fails closed if the token cannot be verified against the public JWKS.
    const { payload } = await verifyAccessToken(data.token);

    res.set("Cache-Control", "no-store");

    return res.json({
      token: data.token,
      claims: {
        sub: payload.sub,
        email: payload.email,
        iss: payload.iss,
        aud: payload.aud,
        iat: payload.iat,
        exp: payload.exp,
      },
    });
  } catch (error) {
    // Log only the error class/code. Never log the cookie or the token.
    console.error(
      "[debug-jwt] JWT generation or verification failed:",
      error?.code ?? error?.name ?? "unknown error",
    );
    return res.status(500).json({ error: "JWT verification failed" });
  }
});

export default router;
