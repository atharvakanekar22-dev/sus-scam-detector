import { describe, it, expect } from "vitest";
import { extractUrls } from "@/lib/analyzer/url/extractor";

describe("URL Extractor Module", () => {
  it("extracts standard HTTPS and HTTP URLs", () => {
    const text = "Visit https://example.com/test and http://insecure.org/page for details.";
    const urls = extractUrls(text);

    expect(urls).toHaveLength(2);
    expect(urls[0].normalizedUrl).toBe("https://example.com/test");
    expect(urls[0].span.text).toBe("https://example.com/test");
    expect(text.slice(urls[0].span.start, urls[0].span.end)).toBe(urls[0].span.text);

    expect(urls[1].normalizedUrl).toBe("http://insecure.org/page");
    expect(urls[1].span.text).toBe("http://insecure.org/page");
    expect(text.slice(urls[1].span.start, urls[1].span.end)).toBe(urls[1].span.text);
  });

  it("extracts URLs starting with www. and normalizes them with https://", () => {
    const text = "Check out www.bankportal.com/login now.";
    const urls = extractUrls(text);

    expect(urls).toHaveLength(1);
    expect(urls[0].originalText).toBe("www.bankportal.com/login");
    expect(urls[0].normalizedUrl).toBe("https://www.bankportal.com/login");
    expect(text.slice(urls[0].span.start, urls[0].span.end)).toBe("www.bankportal.com/login");
  });

  it("strips trailing punctuation without breaking UTF-16 span bounds", () => {
    const cases = [
      "Click here: https://example.com/verify.",
      "Is this real (https://example.com/claim)?",
      "Notice: [https://example.com/notice]!",
      'Visit "https://example.com/quoted", please.',
      "Go to <https://example.com/bracketed> immediately;",
    ];

    for (const msg of cases) {
      const urls = extractUrls(msg);
      expect(urls.length).toBeGreaterThan(0);
      const url = urls[0];
      // Invariant: slice of original string must exactly equal span.text
      expect(msg.slice(url.span.start, url.span.end)).toBe(url.span.text);
      expect(url.span.text).not.toMatch(/[.,;:!?)}>\]]$/);
      expect(url.span.text).not.toMatch(/^[("'<{\[]/);
    }
  });

  it("extracts URLs containing query parameters and fragments", () => {
    const text = "Track parcel: https://courier.com/track?id=99281&carrier=speed#status";
    const urls = extractUrls(text);

    expect(urls).toHaveLength(1);
    expect(urls[0].span.text).toBe("https://courier.com/track?id=99281&carrier=speed#status");
    expect(urls[0].parsed?.searchParams.get("id")).toBe("99281");
    expect(urls[0].parsed?.searchParams.get("carrier")).toBe("speed");
    expect(urls[0].parsed?.hash).toBe("#status");
  });

  it("handles internationalized Punycode domains", () => {
    const text = "Visit https://xn--e1afmkfd.xn--p1ai/account for updates.";
    const urls = extractUrls(text);

    expect(urls).toHaveLength(1);
    expect(urls[0].parsed?.hostname).toBe("xn--e1afmkfd.xn--p1ai");
  });

  it("caps maximum extracted URLs at 10 to prevent resource exhaustion", () => {
    const links = Array.from({ length: 25 }, (_, i) => `https://link${i}.example.com`).join(" ");
    const urls = extractUrls(links);

    expect(urls).toHaveLength(10);
  });

  it("handles empty or link-free messages gracefully", () => {
    expect(extractUrls("")).toHaveLength(0);
    expect(extractUrls("No links here at all, just plain conversation.")).toHaveLength(0);
  });
});
