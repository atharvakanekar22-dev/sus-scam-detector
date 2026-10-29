import { describe, it, expect } from "vitest";
import { analyzeMessage } from "@/lib/analyzer/engine";

describe("Context Awareness, Negation, & Benign Handling Suite", () => {
  it("does not flag routine delivery completed notifications as scam", () => {
    const input = "Your package has been delivered successfully today. Thank you for shopping with us!";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings.some((f) => f.category === "delivery_scam")).toBe(false);
  });

  it("does not flag routine bank transaction and credit alerts as scam", () => {
    const input = "Your a/c 4321 credited by Rs. 8,500 on 28-Oct. Avl bal is Rs 34,200. - ICICI Bank";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings.some((f) => f.category === "financial_pressure")).toBe(false);
  });

  it("handles cybercrime advisory bulletin as protective advisory rather than attack", () => {
    const input =
      "Cybercrime alert: Be alert! Scammers are sending fake electricity power disconnection messages to steal bank OTPs.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("low");
    expect(result.findings.some((f) => f.category === "security_advisory")).toBe(true);
  });

  it("evaluates message containing benign link as low risk", () => {
    const input = "Hey, check out this interesting history article on https://wikipedia.org/wiki/Computer";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.analyzedUrls).toHaveLength(1);
    expect(result.analyzedUrls?.[0].threatLevel).toBe("safe");
  });

  it("evaluates verified official bank portal reference as safe", () => {
    const input = "Welcome to HDFC Bank. Manage your account online securely at https://netbanking.hdfcbank.com";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("low");
    expect(result.analyzedUrls?.[0].brandCheck?.isOfficialDomain).toBe(true);
  });
});
