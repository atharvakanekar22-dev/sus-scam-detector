import { describe, it, expect } from "vitest";
import { isPrivateOrReservedIp, validateUrlForOutboundFetch } from "@/lib/analyzer/url/ssrf";

describe("SSRF & Network Boundary Guard", () => {
  it("detects private, loopback, and link-local IPv4 addresses", () => {
    expect(isPrivateOrReservedIp("127.0.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("127.0.0.5")).toBe(true);
    expect(isPrivateOrReservedIp("10.0.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("10.254.254.254")).toBe(true);
    expect(isPrivateOrReservedIp("172.16.0.1")).toBe(true);
    expect(isPrivateOrReservedIp("172.31.255.255")).toBe(true);
    expect(isPrivateOrReservedIp("192.168.1.1")).toBe(true);
    expect(isPrivateOrReservedIp("169.254.169.254")).toBe(true); // Cloud metadata IP
    expect(isPrivateOrReservedIp("100.64.0.1")).toBe(true); // CGNAT
    expect(isPrivateOrReservedIp("0.0.0.0")).toBe(true);

    // Public IPs should return false
    expect(isPrivateOrReservedIp("8.8.8.8")).toBe(false);
    expect(isPrivateOrReservedIp("1.1.1.1")).toBe(false);
    expect(isPrivateOrReservedIp("142.250.190.46")).toBe(false);
  });

  it("detects loopback and unique-local IPv6 addresses", () => {
    expect(isPrivateOrReservedIp("::1")).toBe(true);
    expect(isPrivateOrReservedIp("fe80::1")).toBe(true);
    expect(isPrivateOrReservedIp("fc00::1")).toBe(true);
    expect(isPrivateOrReservedIp("fd12:3456:789a::1")).toBe(true);
  });

  it("blocks localhost, intranet domains, and unsupported schemes", () => {
    expect(validateUrlForOutboundFetch("http://localhost:3000/api").safe).toBe(false);
    expect(validateUrlForOutboundFetch("http://server.local/page").safe).toBe(false);
    expect(validateUrlForOutboundFetch("http://database.internal:5432").safe).toBe(false);
    expect(validateUrlForOutboundFetch("http://127.0.0.1:8000").safe).toBe(false);
    expect(validateUrlForOutboundFetch("http://169.254.169.254/latest/meta-data/").safe).toBe(false);
    expect(validateUrlForOutboundFetch("file:///etc/passwd").safe).toBe(false);
    expect(validateUrlForOutboundFetch("ftp://ftp.example.com").safe).toBe(false);
    expect(validateUrlForOutboundFetch("javascript:alert(1)").safe).toBe(false);
  });

  it("permits standard public HTTP and HTTPS destinations", () => {
    const validPublic = validateUrlForOutboundFetch("https://example.com/status");
    expect(validPublic.safe).toBe(true);
    expect(validPublic.parsedUrl?.hostname).toBe("example.com");

    const validHttp = validateUrlForOutboundFetch("http://state-power.org/dues");
    expect(validHttp.safe).toBe(true);
    expect(validHttp.parsedUrl?.hostname).toBe("state-power.org");
  });
});
