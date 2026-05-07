/**
 * Web Crypto helpers shared by service-token.ts and api-token.ts.
 *
 * HS256 signing/verification + base64url encoding live here so both modules
 * stay byte-identical and updates (e.g. switching to RS256/JWKS) hit one place.
 */

const textEncoder = new TextEncoder();

export function base64UrlEncode(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function base64UrlEncodeJSON(value: unknown): string {
  return base64UrlEncode(textEncoder.encode(JSON.stringify(value)));
}

export async function hmacSha256(
  secret: string,
  message: string,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    textEncoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, textEncoder.encode(message));
  return new Uint8Array(sig);
}
