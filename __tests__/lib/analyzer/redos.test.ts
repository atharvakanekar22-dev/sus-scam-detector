import { describe, it, expect } from "vitest";
import { DETECTION_RULES, NEGATION_RULES } from "@/lib/analyzer/rules";
import { analyzeMessage } from "@/lib/analyzer/engine";

describe("ReDoS & Catastrophic Backtracking Prevention Suite", () => {
  const allRules = [...DETECTION_RULES, ...NEGATION_RULES];

  it("statically verifies that no rule pattern contains nested quantifiers", () => {
    // Nested quantifier patterns like (a+)+, (.*)*, (\w+)* are catastrophic backtracking risks
    const nestedQuantifierRegex = /(\([^)]*[+*]\)[+*]|\([^)]*\)[+*]\+)/;

    for (const rule of allRules) {
      const patternSource = rule.pattern.source;
      expect(
        nestedQuantifierRegex.test(patternSource),
        `Rule ${rule.id} failed static ReDoS audit: nested repetition detected in ${patternSource}`
      ).toBe(false);
    }
  });

  it("processes 4,000-character repetitive non-matching text in under 50ms", () => {
    // Pathological input: repeated prefix without terminal token
    const pathologicalUrgency = "urgent ".repeat(600) + "xyz";
    const start = performance.now();
    const result = analyzeMessage(pathologicalUrgency);
    const duration = performance.now() - start;

    expect(result).toBeDefined();
    expect(duration).toBeLessThan(50);
  });

  it("processes 4,000-character repetitive link prefix without hang", () => {
    // Pathological input for URL regex
    const pathologicalUrl = "https://" + "a-kyc-".repeat(500) + "portal.in";
    const start = performance.now();
    const result = analyzeMessage(pathologicalUrl);
    const duration = performance.now() - start;

    expect(result).toBeDefined();
    expect(duration).toBeLessThan(50);
  });

  it("processes 4,000-character power disconnection adversarial text in under 50ms", () => {
    const pathologicalPower = "electricity power connection ".repeat(150) + "maintenance";
    const start = performance.now();
    const result = analyzeMessage(pathologicalPower);
    const duration = performance.now() - start;

    expect(result).toBeDefined();
    expect(duration).toBeLessThan(50);
  });
});
