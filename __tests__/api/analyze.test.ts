import { afterEach, beforeEach, describe, it, expect, vi } from "vitest";
import { POST } from "@/app/api/analyze/route";
import { NextRequest } from "next/server";
import * as engineModule from "@/lib/analyzer/engine";

function createPostRequest(body: unknown): NextRequest {
  return new NextRequest("http://localhost:3000/api/analyze", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: typeof body === "string" ? body : JSON.stringify(body),
  });
}

describe("POST /api/analyze API Route Handler", () => {
  beforeEach(() => {
    vi.stubEnv("GEMINI_API_KEY", "");
  });

  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("returns 200 with AnalyzeResponse for high-risk electricity cutoff message", async () => {
    const message =
      "URGENT: Power connection will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer at 98765-43210 or visit http://bit.ly/power-bill";
    const req = createPostRequest({ message });
    const res = await POST(req);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.riskLevel).toBe("high");
    expect(data.heuristicScore).toBeGreaterThanOrEqual(75);
    expect(data.findings.length).toBeGreaterThanOrEqual(3);
    expect(data.metadata.isHeuristic).toBe(true);
    expect(data.metadata.analysisMode).toBe("rules");
    expect(data.metadata.analysisNotice).toContain(
      "Enhanced analysis is not configured"
    );
    expect(data.recommendedSteps.length).toBeGreaterThan(0);
  });

  it("uses Gemini for Hindi input and returns only evidence grounded in the message", async () => {
    const message = "तुरंत अपना OTP भेजें, नहीं तो खाता बंद होगा।";
    const modelAssessment = {
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
            { content: { parts: [{ text: JSON.stringify(modelAssessment) }] } },
          ],
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      )
    );
    vi.stubEnv("GEMINI_API_KEY", "test-api-key");
    vi.stubGlobal("fetch", fetchMock);

    const res = await POST(createPostRequest({ message }));
    const data = await res.json();
    const requestInit = fetchMock.mock.calls[0][1] as RequestInit;

    expect(res.status).toBe(200);
    expect(data.riskLevel).toBe("high");
    expect(data.metadata.analysisMode).toBe("gemini");
    expect(data.findings.some((finding: { ruleId: string }) => finding.ruleId === "AI-01")).toBe(true);
    expect(new Headers(requestInit.headers).get("x-goog-api-key")).toBe(
      "test-api-key"
    );
    expect(String(fetchMock.mock.calls[0][0])).not.toContain("test-api-key");
  });

  it("returns explicit rule-based results if the Gemini service is unavailable", async () => {
    vi.stubEnv("GEMINI_API_KEY", "test-api-key");
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("Network unavailable"))
    );

    const res = await POST(
      createPostRequest({ message: "Please review your pending bill dues." })
    );
    const data = await res.json();

    expect(res.status).toBe(200);
    expect(data.metadata.analysisMode).toBe("rules");
    expect(data.metadata.analysisNotice).toContain(
      "Enhanced analysis could not be reached"
    );
  });

  it("returns 200 with AnalyzeResponse for medium-risk unverified link message", async () => {
    const message =
      "Please review your electricity bill dues before the due date at http://state-power.org";
    const req = createPostRequest({ message });
    const res = await POST(req);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.riskLevel).toBe("medium");
    expect(data.heuristicScore).toBe(35);
    expect(data.findings.some((f: { ruleId: string }) => f.ruleId === "FIN-01")).toBe(true);
    expect(data.findings.some((f: { ruleId: string }) => f.ruleId === "LINK-04")).toBe(true);
  });

  it("returns 200 with Low risk (score 0) for pure protective warning", async () => {
    const message = "State Bank Security: Never share your OTP with anyone.";
    const req = createPostRequest({ message });
    const res = await POST(req);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.riskLevel).toBe("low");
    expect(data.heuristicScore).toBe(0);
    expect(data.findings.some((f: { category: string }) => f.category === "security_advisory")).toBe(true);
    expect(data.findings.some((f: { category: string }) => f.category === "credential_theft")).toBe(false);
  });

  it("returns 200 with High risk for mixed warning plus phishing message", async () => {
    const message =
      "Bank alert: Never share your OTP. However, your KYC has expired, please send us your OTP to avoid card block.";
    const req = createPostRequest({ message });
    const res = await POST(req);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.riskLevel).toBe("high");
    // Verify Clause 1 resulted in advisory
    expect(data.findings.some((f: { category: string }) => f.category === "security_advisory")).toBe(true);
    // Verify Clause 2 caught active credential solicitation outside advisory zone
    expect(data.findings.some((f: { ruleId: string }) => f.ruleId === "CRED-01")).toBe(true);
  });

  it("returns 200 with Low risk for benign meeting invite", async () => {
    const message =
      "Hey Atharva, are we meeting for lunch at 1:30 PM tomorrow at the office cafe?";
    const req = createPostRequest({ message });
    const res = await POST(req);

    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.riskLevel).toBe("low");
    expect(data.heuristicScore).toBe(0);
    expect(data.findings.length).toBe(0);
  });

  it("returns 400 for input under minimum length (<5 characters)", async () => {
    const req = createPostRequest({ message: "Hi" });
    const res = await POST(req);

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error.code).toBe("INVALID_INPUT");
    expect(data.error.message).toContain("at least 5 characters");
  });

  it("returns 400 for input exceeding 5,000 characters", async () => {
    const req = createPostRequest({ message: "A".repeat(5001) });
    const res = await POST(req);

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error.code).toBe("INVALID_INPUT");
    expect(data.error.message).toContain("maximum limit");
  });

  it("returns 400 for whitespace-only input", async () => {
    const req = createPostRequest({ message: "    \n\t   " });
    const res = await POST(req);

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error.code).toBe("INVALID_INPUT");
  });

  it("returns 400 for malformed non-JSON payload", async () => {
    const req = new NextRequest("http://localhost:3000/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "this is not json {",
    });
    const res = await POST(req);

    expect(res.status).toBe(400);
    const data = await res.json();
    expect(data.error.code).toBe("INVALID_INPUT");
    expect(data.error.message).toContain("Invalid JSON");
  });

  it("returns 500 when forceError is true in non-production environments", async () => {
    const req = createPostRequest({
      message: "Please send us your OTP immediately to verify your account.",
      forceError: true,
    });
    const res = await POST(req);

    expect(res.status).toBe(500);
    const data = await res.json();
    expect(data.error.code).toBe("INTERNAL_ERROR");
    expect(data.error.message).toContain("Simulated analysis server exception");
  });

  it("ignores forceError in production environment and executes normal analysis", async () => {
    const originalEnv = process.env.NODE_ENV;
    try {
      // @ts-expect-error mutating readonly NODE_ENV for test
      process.env.NODE_ENV = "production";

      const req = createPostRequest({
        message: "Please send us your OTP immediately to verify your account.",
        forceError: true,
      });
      const res = await POST(req);

      // In production, forceError is ignored and real analysis executes
      expect(res.status).toBe(200);
      const data = await res.json();
      expect(data.riskLevel).toBe("high");
      expect(data.heuristicScore).toBeGreaterThanOrEqual(55);
    } finally {
      // @ts-expect-error restoring original NODE_ENV
      process.env.NODE_ENV = originalEnv;
    }
  });

  it("does not expose internal exception details or stack traces in production error responses", async () => {
    const originalEnv = process.env.NODE_ENV;
    const spy = vi.spyOn(engineModule, "analyzeMessage").mockImplementationOnce(() => {
      throw new Error("InternalServerSecretLeak: /app/secret-keys.pem at line 42");
    });

    try {
      // @ts-expect-error mutating readonly NODE_ENV for test
      process.env.NODE_ENV = "production";

      const req = createPostRequest({
        message: "Please review your pending bill dues immediately.",
      });
      const res = await POST(req);

      expect(res.status).toBe(500);
      const data = await res.json();
      expect(data.error.code).toBe("INTERNAL_ERROR");
      expect(data.error.message).toBe("An unexpected error occurred during message inspection.");
      // Ensure details does not expose the internal error message or paths
      expect(data.error.details).toBeUndefined();
      expect(JSON.stringify(data)).not.toContain("secret-keys.pem");
    } finally {
      spy.mockRestore();
      // @ts-expect-error restoring original NODE_ENV
      process.env.NODE_ENV = originalEnv;
    }
  });

  it("provides internal error details in non-production environments for local debugging", async () => {
    const spy = vi.spyOn(engineModule, "analyzeMessage").mockImplementationOnce(() => {
      throw new Error("LocalDebugFailure: engine failed on token");
    });

    try {
      const req = createPostRequest({
        message: "Please review your pending bill dues immediately.",
      });
      const res = await POST(req);

      expect(res.status).toBe(500);
      const data = await res.json();
      expect(data.error.code).toBe("INTERNAL_ERROR");
      expect(data.error.details).toBe("LocalDebugFailure: engine failed on token");
    } finally {
      spy.mockRestore();
    }
  });
});
