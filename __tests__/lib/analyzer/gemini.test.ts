import { afterEach, describe, expect, it, vi } from "vitest";
import { analyzeMessage } from "@/lib/analyzer/engine";
import {
  analyzeWithGemini,
  GeminiProviderError,
  mergeGeminiAssessment,
} from "@/lib/analyzer/gemini";

describe("Gemini scam assessment", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("uses the server API key and grounds Hindi evidence in the original message", async () => {
    const message = "तुरंत अपना OTP भेजें, नहीं तो खाता बंद होगा।";
    const assessment = {
      riskLevel: "high",
      summary: "यह संदेश OTP मांगता है और खाता बंद करने की धमकी देता है।",
      findings: [
        {
          category: "credential_theft",
          title: "OTP की मांग",
          description: "संदेश में OTP भेजने के लिए कहा गया है।",
          severity: "high",
          evidence: "अपना OTP भेजें",
        },
      ],
      recommendedSteps: ["OTP साझा न करें।"],
    };
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(
        JSON.stringify({
          candidates: [
            { content: { parts: [{ text: JSON.stringify(assessment) }] } },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    );
    vi.stubGlobal("fetch", fetchMock);

    const aiResult = await analyzeWithGemini(message, "test-api-key");
    const rulesResult = analyzeMessage(message);
    const combined = mergeGeminiAssessment(message, rulesResult, aiResult);
    const requestInit = fetchMock.mock.calls[0][1] as RequestInit;

    expect(fetchMock).toHaveBeenCalledOnce();
    expect(new Headers(requestInit.headers).get("x-goog-api-key")).toBe(
      "test-api-key"
    );
    expect(fetchMock.mock.calls[0][0]).not.toContain("test-api-key");
    expect(JSON.stringify(JSON.parse(String(requestInit.body)))).toContain(message);
    expect(combined.metadata.analysisMode).toBe("gemini");
    expect(combined.riskLevel).toBe("high");
    expect(combined.findings).toContainEqual(
      expect.objectContaining({
        ruleId: "AI-01",
        category: "credential_theft",
        span: {
          start: message.indexOf("अपना OTP भेजें"),
          end: message.indexOf("अपना OTP भेजें") + "अपना OTP भेजें".length,
          text: "अपना OTP भेजें",
        },
      })
    );
  });

  it("reports provider throttling instead of hiding it", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("quota", { status: 429 }))
    );

    await expect(
      analyzeWithGemini("Please verify your account now.", "test-api-key")
    ).rejects.toThrow(
      "Enhanced analysis is temporarily unavailable. Showing rule-based results."
    );
  });

  it("rejects a non-low model verdict when none of its evidence matches the message", () => {
    const message = "Hello, see you at lunch tomorrow.";
    const rulesResult = analyzeMessage(message);

    expect(() =>
      mergeGeminiAssessment(message, rulesResult, {
        riskLevel: "high",
        summary: "This is suspicious.",
        findings: [
          {
            category: "credential_theft",
            title: "Credential request",
            description: "Asks for an OTP.",
            severity: "high",
            evidence: "send your OTP",
          },
        ],
        recommendedSteps: [],
      })
    ).toThrow(GeminiProviderError);
  });
});
