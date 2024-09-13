import { createHmac } from "node:crypto";
import { env } from "../env";

// **TODO:** consider using a more secure way to manage secrets.
const masterSecret = Buffer.from(env.SECRET_KEY, "hex");

/**
 * Calculates the HMAC-SHA256 hash of the provided data using the given key.
 *
 * @param key The key to use for the HMAC calculation (string or Buffer).
 * @param data The data to hash (string or Buffer).
 * @returns The HMAC-SHA256 hash in hexadecimal format.
 */
function hmacSha256(key: string | Buffer, data: string | Buffer): string {
  try {
    const hmac = createHmac("sha256", key);
    hmac.update(data);
    return hmac.digest("hex");
  } catch (error) {
    // Handle potential errors during HMAC calculation
    console.error("Error calculating HMAC:", error);
    throw error; // Re-throw the error or handle it appropriately
  }
}

/**
 * Calculates a signature for the provided data using the master secret.
 *
 * @param timestamp The timestamp of the request.
 * @param contentType The content type of the request.
 * @param deviceID The ID of the device making the request.
 * @param fileHash The hash of the file being uploaded.
 * @returns The calculated signature.
 */
export function calculateSignature(
  timestamp: string,
  contentType: string,
  deviceID: string,
  fileHash: string
): string {
  // **TODO:** Add input validation for timestamp, contentType, deviceID, fileHash

  const data = timestamp + contentType + deviceID + fileHash;
  return hmacSha256(masterSecret, data);
}

/**
 * Verifies if two strings are equal in a constant-time manner to prevent timing attacks.
 * This is typically used for secure comparison of hashes or secrets.
 *
 * @param hash1 The first hash string.
 * @param hash2 The second hash string.
 * @returns True if the hashes are equal, false otherwise.
 */
export function verifySignature(hash1: string, hash2: string): boolean {
  if (hash1.length !== hash2.length) {
    return false;
  }

  let result = 0;
  for (let i = 0; i < hash1.length; i++) {
    // Perform bitwise XOR on the character codes and accumulate the result
    result |= hash1.charCodeAt(i) ^ hash2.charCodeAt(i);
  }

  // If result is 0, all characters were the same
  return result === 0;
}