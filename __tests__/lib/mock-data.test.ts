import { describe, it, expect } from "vitest";
import { simulateMockAnalysis, SAMPLE_MESSAGES } from "@/lib/mock-data";

describe("Mock Data Fixtures & Simulation", () => {
  it("provides sample test messages with required fields", () => {
    expect(SAMPLE_MESSAGES.length).toBeGreaterThanOrEqual(3);
    for (const sample of SAMPLE_MESSAGES) {
      expect(sample.id).toBeDefined();
      expect(sample.label).toBeDefined();
      expect(sample.text.length).toBeGreaterThan(10);
      expect(["high", "medium", "low"]).toContain(sample.expectedRisk);
    }
  });

  it("returns high-risk mock result for urgent electricity cutoff message", async () => {
    const result = await simulateMockAnalysis("URGENT: electricity disconnection notice");
    expect(result.riskLevel).toBe("high");
    expect(result.riskScorePercent).toBeGreaterThanOrEqual(70);
    expect(result.findings.length).toBeGreaterThan(0);
    expect(result.isMock).toBe(true);
  });

  it("returns medium-risk mock result for bank KYC expiry message", async () => {
    const result = await simulateMockAnalysis("Your SBI account KYC has expired. Verify PAN.");
    expect(result.riskLevel).toBe("medium");
    expect(result.findings.some((f) => f.category === "personal_data")).toBe(true);
    expect(result.isMock).toBe(true);
  });

  it("returns low-risk mock result for benign lunch meeting invite", async () => {
    const result = await simulateMockAnalysis("Hey, are we having lunch tomorrow at the cafe?");
    expect(result.riskLevel).toBe("low");
    expect(result.isMock).toBe(true);
  });

  it("throws simulated error when forceError is true", async () => {
    await expect(simulateMockAnalysis("Any message", true)).rejects.toThrow(
      /Simulated network timeout/
    );
  });
});
