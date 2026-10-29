import { describe, it, expect } from "vitest";
import { analyzeMessage } from "@/lib/analyzer/engine";

describe("Expanded Scam Categories Integration Suite", () => {
  it("flags UPI QR code receipt trap as high risk", () => {
    const input = "Scan this QR code to receive Rs 5,000 cashback directly in your bank account.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "UPI-01")).toBe(true);
    expect(result.recommendedSteps.some((s) => s.text.includes("UPI PIN"))).toBe(true);
  });

  it("flags UPI PIN request to receive funds as high risk", () => {
    const input = "Please enter your UPI PIN to receive money of Rs 2,500 from electricity board refund.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "UPI-02")).toBe(true);
  });

  it("flags KYC expiry and account blocking threat as high risk", () => {
    const input =
      "Dear customer, your PAN card KYC has expired. Your account will be blocked within 24 hours. Update immediately.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "KYC-01")).toBe(true);
  });

  it("flags fake parcel delivery with rescheduling fee demand as high risk", () => {
    const input =
      "Your parcel is held at the sorting hub due to incomplete address. Pay redelivery fee of Rs 48 and reschedule: http://bit.ly/redelivery-update";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "DELIV-01")).toBe(true);
    expect(result.recommendedSteps.some((s) => s.text.includes("courier"))).toBe(true);
  });

  it("flags customs detention fee extortion as high risk", () => {
    const input =
      "Customs office notification: International parcel detained at airport. Pay clearance duty Rs 3,500 to release shipment.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "DELIV-02")).toBe(true);
  });

  it("flags work-from-home job with advance registration fee as high risk", () => {
    const input =
      "Part-time job offer: Like YouTube videos and earn Rs 3000 - 8000 daily from home. Pay refundable registration fee Rs 500 for the job kit.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "JOB-01")).toBe(true);
    expect(result.findings.some((f) => f.ruleId === "JOB-02")).toBe(true);
    expect(result.recommendedSteps.some((s) => s.text.includes("Legitimate companies"))).toBe(true);
  });

  it("flags guaranteed cryptocurrency doubling scheme with action link as high risk", () => {
    const input =
      "Guaranteed 100% daily profit! Double your cryptocurrency with our automated trading plan: http://crypto-doubler.xyz";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "INV-01")).toBe(true);
  });

  it("flags digital arrest and police warrant intimidation as high risk", () => {
    const input =
      "Digital arrest order from CBI headquarters: Arrest warrant issued for money laundering through illegal consignment. Connect with officer immediately.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "GOV-01")).toBe(true);
    expect(result.summary).toContain("government or law enforcement coercion");
    expect(result.recommendedSteps.some((s) => s.text.includes("digital arrests"))).toBe(true);
  });

  it("flags remote desktop application installation lure as high risk", () => {
    const input =
      "To resolve your electricity bill dispute, install AnyDesk on your mobile phone and grant permission to our officer.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "REMOTE-01")).toBe(true);
    expect(result.recommendedSteps.some((s) => s.text.includes("AnyDesk"))).toBe(true);
  });

  it("flags suspicious APK application download prompt as high risk", () => {
    const input =
      "Dear user, your electricity connection rewards are ready. Download and install electricity_bill.apk to claim your bonus.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "ATTACH-01")).toBe(true);
    expect(result.recommendedSteps.some((s) => s.text.includes("APK files"))).toBe(true);
  });

  it("flags fraudulent virus alert and tech support scareware as high risk", () => {
    const input =
      "Warning: 3 Trojan viruses detected on your smartphone! Call support helpline immediately at 98765-43210 to clean now.";
    const result = analyzeMessage(input);

    expect(result.riskLevel).toBe("high");
    expect(result.findings.some((f) => f.ruleId === "TECH-01")).toBe(true);
  });

  it("flags accidental money credit refund trap", () => {
    const input =
      "Sir, Rs 25,000 was mistakenly credited to your account by mistake. Please refund and transfer back immediately.";
    const result = analyzeMessage(input);

    expect(result.findings.some((f) => f.ruleId === "REFUND-01")).toBe(true);
  });
});
