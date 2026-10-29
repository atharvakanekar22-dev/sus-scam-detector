/**
 * SSRF and Network Boundary Guard
 *
 * Implements strict host, IP range, and scheme validation to prevent
 * Server-Side Request Forgery (SSRF) and intranet port scanning.
 */

// Blocked private and reserved IPv4 prefixes (CIDR blocks)
const PRIVATE_IPV4_RANGES = [
  { prefix: "0.", mask: "0.0.0.0/8" },
  { prefix: "10.", mask: "10.0.0.0/8" },
  { prefix: "127.", mask: "127.0.0.0/8" },
  { prefix: "169.254.", mask: "169.254.0.0/16" },
  { prefix: "192.168.", mask: "192.168.0.0/16" },
  { prefix: "224.", mask: "224.0.0.0/4" },
  { prefix: "240.", mask: "240.0.0.0/4" },
  { prefix: "255.255.255.255", mask: "broadcast" },
];

/**
 * Checks if an IPv4 address is in private 172.16.0.0 - 172.31.255.255 range.
 */
function isPrivate172(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length === 4 && parts[0] === 172) {
    return parts[1] >= 16 && parts[1] <= 31;
  }
  return false;
}

/**
 * Checks if an IPv4 address is in Carrier Grade NAT 100.64.0.0/10 range.
 */
function isCgnat(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length === 4 && parts[0] === 100) {
    return parts[1] >= 64 && parts[1] <= 127;
  }
  return false;
}

/**
 * Checks whether an IPv4 string is within any private, loopback, or reserved range.
 */
export function isPrivateOrReservedIp(ip: string): boolean {
  const trimmed = ip.trim();

  // Check simple IPv4 prefixes
  for (const range of PRIVATE_IPV4_RANGES) {
    if (trimmed.startsWith(range.prefix)) {
      return true;
    }
  }

  if (isPrivate172(trimmed) || isCgnat(trimmed)) {
    return true;
  }

  // IPv6 loopback / unique local / link-local / unspecified
  const lower = trimmed.toLowerCase();
  if (
    lower === "::1" ||
    lower === "::" ||
    lower.startsWith("fe80:") ||
    lower.startsWith("fc") ||
    lower.startsWith("fd") ||
    lower.startsWith("::ffff:127.") ||
    lower.startsWith("::ffff:10.") ||
    lower.startsWith("::ffff:192.168.")
  ) {
    return true;
  }

  return false;
}

/**
 * Validates whether a URL is strictly safe for potential outbound HTTP fetching,
 * completely rejecting intranet, localhost, private IP, and unsupported schemes.
 */
export function validateUrlForOutboundFetch(rawUrl: string): {
  safe: boolean;
  reason?: string;
  parsedUrl?: URL;
} {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { safe: false, reason: "Malformed or unparseable URL." };
  }

  const protocol = parsed.protocol.toLowerCase();
  if (protocol !== "http:" && protocol !== "https:") {
    return {
      safe: false,
      reason: `Unsupported URL protocol '${protocol}'. Only HTTP and HTTPS are permitted.`,
    };
  }

  const hostname = parsed.hostname.toLowerCase().trim();

  // Localhost or reserved local hostnames
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".lan") ||
    hostname.endsWith(".home.arpa")
  ) {
    return {
      safe: false,
      reason: `Access to local/internal destination '${hostname}' is strictly blocked.`,
    };
  }

  // Check if hostname is directly an IP address
  if (isPrivateOrReservedIp(hostname)) {
    return {
      safe: false,
      reason: `Direct connection to private or loopback IP range '${hostname}' is blocked.`,
    };
  }

  return { safe: true, parsedUrl: parsed };
}
