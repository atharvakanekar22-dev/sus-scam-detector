import { describe, it, expect } from "vitest";
import { evaluateBrandImpersonation, isOfficialSubdomain } from "@/lib/analyzer/url/brands";

describe("Brand Intelligence & Lookalike Detection", () => {
  it("verifies exact official domains", () => {
    expect(evaluateBrandImpersonation("sbi.co.in")).toMatchObject({
      isOfficialDomain: true,
      isLookalike: false,
      confidence: "confirmed",
    });

    expect(evaluateBrandImpersonation("hdfcbank.com")).toMatchObject({
      isOfficialDomain: true,
      isLookalike: false,
      confidence: "confirmed",
    });

    expect(evaluateBrandImpersonation("paytm.com")).toMatchObject({
      isOfficialDomain: true,
      isLookalike: false,
      confidence: "confirmed",
    });
  });

  it("verifies authorized legitimate subdomains", () => {
    expect(isOfficialSubdomain("netbanking.hdfcbank.com", "hdfcbank.com")).toBe(true);
    expect(isOfficialSubdomain("retail.onlinesbi.sbi", "onlinesbi.sbi")).toBe(true);
    expect(isOfficialSubdomain("pay.google.com", "google.com")).toBe(true);

    const sbiSub = evaluateBrandImpersonation("retail.onlinesbi.sbi");
    expect(sbiSub.isOfficialDomain).toBe(true);
    expect(sbiSub.isLookalike).toBe(false);

    const hdfcSub = evaluateBrandImpersonation("netbanking.hdfcbank.com");
    expect(hdfcSub.isOfficialDomain).toBe(true);
    expect(hdfcSub.isLookalike).toBe(false);
  });

  it("identifies deceptive brand mimics containing hyphenated brand names", () => {
    const deceptiveDomains = [
      "sbi-kyc-verify-portal.in",
      "hdfc-security-login.com",
      "icici-bank-alert.xyz",
      "paytm-cashback-claim.net",
      "phonepe-reward-offer.org",
      "indiapost-parcel-reschedule.com",
    ];

    for (const domain of deceptiveDomains) {
      const result = evaluateBrandImpersonation(domain);
      expect(result.isOfficialDomain).toBe(false);
      expect(result.isLookalike).toBe(true);
      expect(result.confidence).toBe("likely");
      expect(result.claimedBrand).toBeDefined();
    }
  });

  it("detects typosquatting via single-character edits", () => {
    const typosquats = [
      "hdfcbannk.com", // extra 'n'
      "paytmm.com", // extra 'm'
    ];

    for (const domain of typosquats) {
      const result = evaluateBrandImpersonation(domain);
      expect(result.isOfficialDomain).toBe(false);
      expect(result.isLookalike).toBe(true);
    }
  });

  it("marks unrecognized non-brand domains as inconclusive without false alerts", () => {
    const neutralDomains = [
      "github.com",
      "medium.com",
      "myntra.com",
      "random-blog-domain.org",
    ];

    for (const domain of neutralDomains) {
      const result = evaluateBrandImpersonation(domain);
      expect(result.isOfficialDomain).toBe(false);
      expect(result.isLookalike).toBe(false);
      expect(result.confidence).toBe("inconclusive");
    }
  });
});
