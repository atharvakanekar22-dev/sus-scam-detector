import { describe, it, expect } from "vitest";
import { extractUrls } from "@/lib/analyzer/url/extractor";
import { analyzeExtractedUrl } from "@/lib/analyzer/url/heuristics";

describe("URL Heuristics Engine", () => {
  it("flags numeric IP address hosts with high threat level", () => {
    const [extracted] = extractUrls("Visit http://192.168.1.100/admin for router settings");
    const analyzed = analyzeExtractedUrl(extracted);

    expect(analyzed.isSuspicious).toBe(true);
    expect(analyzed.threatLevel).toBe("high");
    expect(analyzed.indicators.some((i) => i.code === "IP_ADDRESS_HOST")).toBe(true);
  });

  it("flags public URL shorteners", () => {
    const [extracted] = extractUrls("Track your delivery at https://bit.ly/3x8AbCd now");
    const analyzed = analyzeExtractedUrl(extracted);

    expect(analyzed.indicators.some((i) => i.code === "URL_SHORTENER")).toBe(true);
    expect(analyzed.threatLevel).toBe("medium");
  });

  it("flags deceptive userinfo @ authority formatting", () => {
    const [extracted] = extractUrls("Login at https://sbi.co.in@evil-portal.net/login");
    const analyzed = analyzeExtractedUrl(extracted);

    expect(analyzed.indicators.some((i) => i.code === "USERINFO_TRICK")).toBe(true);
    expect(analyzed.threatLevel).toBe("high");
  });

  it("flags non-standard ports", () => {
    const [extracted] = extractUrls("Access web console: https://example.com:8443/dashboard");
    const analyzed = analyzeExtractedUrl(extracted);

    expect(analyzed.indicators.some((i) => i.code === "UNUSUAL_PORT")).toBe(true);
  });

  it("flags credential and KYC verification paths", () => {
    const [extracted] = extractUrls("Verify your identity at https://secure-server.net/kyc-verification");
    const analyzed = analyzeExtractedUrl(extracted);

    expect(analyzed.indicators.some((i) => i.code === "CREDENTIAL_PATH")).toBe(true);
  });

  it("flags open redirect parameters", () => {
    const [extracted] = extractUrls("Click here: https://example.org/jump?redirect=https://destination.xyz");
    const analyzed = analyzeExtractedUrl(extracted);

    expect(analyzed.indicators.some((i) => i.code === "SUSPICIOUS_REDIRECT")).toBe(true);
  });

  it("flags insecure HTTP protocol as a low severity signal without marking as high threat", () => {
    const [extracted] = extractUrls("Read this article at http://classic-blog.org/news");
    const analyzed = analyzeExtractedUrl(extracted);

    expect(analyzed.indicators.some((i) => i.code === "INSECURE_HTTP")).toBe(true);
    expect(analyzed.threatLevel).toBe("low");
  });

  it("evaluates benign well-known URLs as safe without false alarm inflation", () => {
    const benignUrls = [
      "Check out shoes on https://myntra.com",
      "Read reference documentation on https://wikipedia.org/wiki/Phishing",
      "Source repository hosted at https://github.com/atharvakanekar22-dev/sus-scam-detector",
    ];

    for (const msg of benignUrls) {
      const [extracted] = extractUrls(msg);
      const analyzed = analyzeExtractedUrl(extracted);
      expect(analyzed.threatLevel).toBe("safe");
      expect(analyzed.isSuspicious).toBe(false);
    }
  });
});
