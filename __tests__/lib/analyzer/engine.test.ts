import { describe, it, expect } from "vitest";
import { analyzeMessage } from "@/lib/analyzer/engine";

describe("Analysis Engine Integration & Regression Suite (26 Cases)", () => {
  it("TC-01: Pure Warning - Never share your OTP with anyone", () => {
    const input = "State Bank Security: Never share your OTP with anyone.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings.some((f) => f.category === "credential_theft")).toBe(false);
    expect(result.findings.some((f) => f.category === "security_advisory")).toBe(true);
  });

  it("TC-02: Pure Phishing - Send us your OTP to verify account", () => {
    const input = "Send us your OTP to verify your account and unlock your card.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(55);
    const credFinding = result.findings.find((f) => f.ruleId === "CRED-01");
    expect(credFinding).toBeDefined();
    expect(credFinding?.span.text.toLowerCase()).toContain("send us your otp");
  });

  it("TC-03: Mixed - Warning followed by scam in separate clause", () => {
    const input =
      "Bank alert: Never share your OTP. However, your KYC has expired, please send us your OTP to avoid card block.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    // Verify Clause 1 resulted in advisory
    expect(result.findings.some((f) => f.category === "security_advisory")).toBe(true);
    // Verify Clause 2 was NOT suppressed and caught active solicitation
    expect(result.findings.some((f) => f.ruleId === "CRED-01")).toBe(true);
  });

  it("TC-04: Cautionary Advisory - do not share password", () => {
    const input = "Caution: do not share your OTP or password with unauthorized callers.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings.some((f) => f.category === "credential_theft")).toBe(false);
  });

  it("TC-05: Electricity Cutoff Extortion", () => {
    const input =
      "URGENT: Power connection will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer at 98765-43210 or visit http://bit.ly/power-bill";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(75);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("URG-01");
    expect(ruleIds).toContain("IMP-01");
    expect(ruleIds).toContain("LINK-01");
    expect(ruleIds).toContain("FIN-01");
  });

  it("TC-06: Bank KYC Suspension Phishing", () => {
    const input =
      "Dear customer, your net banking access will be suspended within 24 hours. Re-verify your Aadhaar and PAN card at https://sbi-kyc-verify-portal.in";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(75);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("CRED-02");
    expect(ruleIds).toContain("URG-02");
    expect(ruleIds).toContain("LINK-03");
  });

  it("TC-07: Lottery Advance Fee Scam", () => {
    const input =
      "Congratulations you won lottery Rs. 25,00,000! Transfer advance processing fee Rs 1,000 to release prize.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.heuristicScore).toBeGreaterThanOrEqual(75);
    const ruleIds = result.findings.map((f) => f.ruleId);
    expect(ruleIds).toContain("FIN-02");
    expect(ruleIds).toContain("FIN-03");
  });

  it("TC-08: Benign Meeting Invite", () => {
    const input = "Hey Atharva, are we meeting for lunch at 1:30 PM tomorrow at the office cafe?";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
    expect(result.findings).toHaveLength(0);
  });

  it("TC-09: Benign Bank Credit SMS", () => {
    const input = "Your a/c 1234 credited with INR 5,000 on 17-Oct. Available balance: INR 24,500. - HDFC Bank";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
  });

  it("TC-10: Benign Clinic Appointment Reminder", () => {
    const input = "Reminder: You have an appointment with Dr. Sharma tomorrow at 10 AM. Reschedule: 011-23456789.";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBe(0);
  });

  it("TC-11: Benign E-commerce Flash Sale", () => {
    const input = "Hurry! Flash sale ends today. Get 50% discount on shoes at https://myntra.com";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.heuristicScore).toBeLessThanOrEqual(24);
  });

  it("TC-12: Unverified Link with Pending Dues", () => {
    const input = "Please review your pending electricity bill dues before the due date at http://state-power.org";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("medium");
    expect(result.heuristicScore).toBe(35);
  });

  it("TC-13: Duplicate Signal Spamming (Deduplication Check)", () => {
    const input = "URGENT! URGENT! Please act immediately, this is urgent!";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    // URG-03 contributes only once (15 points)
    expect(result.heuristicScore).toBe(15);
  });

  it("TC-14: Raw IP Address Phishing", () => {
    const input = "Provide your net banking password at http://192.168.1.100/login";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "LINK-02")).toBe(true);
    expect(result.findings.some((f) => f.ruleId === "CRED-03")).toBe(true);
  });

  it("TC-15: Unicode and Emojis Highlight Offset Accuracy", () => {
    const input = "URGENT 🚨 electricity blackout tonight ⚡ call officer at 98765-43210";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("high");
    // Verify each finding matches its slice exactly
    for (const f of result.findings) {
      expect(input.slice(f.span.start, f.span.end)).toBe(f.span.text);
    }
  });

  it("TC-16: Quoted Scam Text", () => {
    const input = 'Security news: Scammers are sending "Your electricity connection will be disconnected tonight".';
    const result = analyzeMessage(input);
    expect(result.findings.some((f) => f.ruleId === "URG-01")).toBe(true);
  });

  it("TC-17: Boundary: Minimum 5 characters", () => {
    const input = "Hello";
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
  });

  it("TC-18: Boundary: Exactly 5,000 characters", () => {
    const input = "A".repeat(5000);
    expect(input.length).toBe(5000);
    const result = analyzeMessage(input);
    expect(result.riskLevel).toBe("low");
    expect(result.metadata.charCount).toBe(5000);
  });

  it("TC-19: Error: Under Minimum Length (<5 chars)", () => {
    expect(() => analyzeMessage("Hi")).toThrow(/at least 5 characters/i);
  });

  it("TC-20: Error: Over Maximum Length (5,001 chars)", () => {
    const overLength = "A".repeat(5001);
    expect(() => analyzeMessage(overLength)).toThrow(/maximum limit/i);
  });

  it("TC-21: Error: Empty String", () => {
    expect(() => analyzeMessage("")).toThrow(/at least 5 characters/i);
  });

  it("TC-22: Error: Whitespace Only", () => {
    expect(() => analyzeMessage("   \t\n\r\n   ")).toThrow(/at least 5 characters/i);
  });

  it("TC-23: Stress: Repetitive Urgency Words", () => {
    const input = "urgent ".repeat(500) + "end now";
    const start = performance.now();
    const result = analyzeMessage(input);
    const duration = performance.now() - start;
    expect(result.riskLevel).toBe("low");
    expect(duration).toBeLessThan(100);
  });

  it("TC-24: Stress: Repetitive Subdomain Mimics", () => {
    const input = "https://sbi-" + "verify-".repeat(300) + "portal.in";
    const start = performance.now();
    const result = analyzeMessage(input);
    const duration = performance.now() - start;
    expect(duration).toBeLessThan(100);
    expect(result).toBeDefined();
    expect(result.metadata.charCount).toBe(input.length);
  });

  it("TC-25: Span Slicing Invariant across all findings", () => {
    const input =
      "URGENT: your electricity power connection will be cut-off tonight at 9:30 PM. Pay dues at http://bit.ly/pay and call 98765-43210.";
    const result = analyzeMessage(input);
    expect(result.findings.length).toBeGreaterThan(0);
    for (const f of result.findings) {
      expect(input.slice(f.span.start, f.span.end)).toBe(f.span.text);
      expect(f.span.start).toBeGreaterThanOrEqual(0);
      expect(f.span.end).toBeLessThanOrEqual(input.length);
    }
  });

  it("TC-26: Toll-Free Safe Channel does not trigger IMP-01", () => {
    const input = "Please contact our customer care at 1800-11-2211 for assistance with your bank.";
    const result = analyzeMessage(input);
    expect(result.findings.some((f) => f.ruleId === "IMP-01")).toBe(false);
  });
});
