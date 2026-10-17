import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import Home from "@/app/page";
import { POST } from "@/app/api/analyze/route";
import { NextRequest } from "next/server";

describe("Sus Page Full Flow Integration with Real Engine", () => {
  let failNextAnalysisRequest = false;

  beforeEach(() => {
    failNextAnalysisRequest = false;
    vi.stubEnv("GEMINI_API_KEY", "");
    vi.spyOn(global, "fetch").mockImplementation(async (input, init) => {
      const urlStr = typeof input === "string" ? input : input.toString();
      if (urlStr.includes("/api/analyze")) {
        if (failNextAnalysisRequest) {
          failNextAnalysisRequest = false;
          return new Response(
            JSON.stringify({ error: { message: "Temporary analysis failure" } }),
            { status: 500, headers: { "Content-Type": "application/json" } }
          );
        }
        const req = new NextRequest("http://localhost:3000/api/analyze", {
          method: init?.method || "POST",
          headers: init?.headers as HeadersInit,
          body: init?.body as BodyInit,
        });
        return POST(req);
      }
      return fetch(input, init);
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
  });

  it("completes full scan flow from manual entry to real engine result and reset", async () => {
    render(<Home />);

    expect(screen.getByRole("heading", { name: "SUS", level: 1 })).toBeInTheDocument();
    expect(screen.queryByText(/PS-01: Scam Spotter/)).not.toBeInTheDocument();
    expect(screen.queryByText(/Heuristic Assessment Disclaimer/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Privacy & Data Safeguards/i)).not.toBeInTheDocument();

    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, {
      target: {
        value:
          "URGENT: Dear customer, your electricity power connection will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity verification officer at 98765-43210 or click http://bit.ly/power-bill-update to prevent immediate blackout.",
      },
    });

    // Click Analyze Message
    const analyzeBtn = screen.getByRole("button", { name: /Analyze Message/i });
    fireEvent.click(analyzeBtn);

    // Expect loading state first
    expect(screen.getByText(/Checking message.../i)).toBeInTheDocument();

    // Expect real engine results to appear
    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "High risk" })).toBeInTheDocument();
      },
      { timeout: 2000 }
    );

    // Verify evidence highlights and score
    expect(screen.getByRole("heading", { name: "Warning signs" })).toBeInTheDocument();
    expect(screen.getAllByText(/Pressures you to act quickly/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Contains a suspicious link/i)).toBeInTheDocument();

    // Reset flow
    const resetBtn = screen.getByRole("button", { name: /Check another message/i });
    fireEvent.click(resetBtn);

    // Results panel should disappear
    expect(screen.queryByRole("heading", { name: "High risk" })).not.toBeInTheDocument();
  });

  it("handles low-risk benign message and renders clean findings state", async () => {
    render(<Home />);

    // Select benign sample
    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, {
      target: {
        value:
          "Hey Atharva, are we still meeting for lunch at 1:30 PM tomorrow at the cafe near the office?",
      },
    });

    // Submit
    const analyzeBtn = screen.getByRole("button", { name: /Analyze Message/i });
    fireEvent.click(analyzeBtn);

    await waitFor(
      () => {
        expect(
          screen.getByRole("heading", { name: "No common warning signs" })
        ).toBeInTheDocument();
      },
      { timeout: 2000 }
    );

    expect(
      screen.getByRole("img", { name: /No common warning signs; rule score 0 out of 100/i })
    ).toBeInTheDocument();
    expect(screen.getAllByText(/No common scam signs were found/i).length).toBeGreaterThan(0);
  });

  it("handles mixed protective warning and scam in separate clauses", async () => {
    render(<Home />);

    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, {
      target: {
        value:
          "Bank alert: Never share your OTP. However, your KYC has expired, please send us your OTP to avoid card block.",
      },
    });

    const analyzeBtn = screen.getByRole("button", { name: /Analyze Message/i });
    fireEvent.click(analyzeBtn);

    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "High risk" })).toBeInTheDocument();
      },
      { timeout: 2000 }
    );

    // Verify advisory and credential theft findings
    expect(screen.getByText(/Safety warning/i)).toBeInTheDocument();
    expect(screen.getByText(/Asks for private codes or details/i)).toBeInTheDocument();
  });

  it("handles simulated error state and error recovery", async () => {
    render(<Home />);

    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, {
      target: {
        value:
          "URGENT: Dear customer, your electricity power connection will be disconnected tonight at 9:30 PM because your previous month bill was not updated. Please immediately contact our electricity verification officer at 98765-43210 or click http://bit.ly/power-bill-update to prevent immediate blackout.",
      },
    });

    failNextAnalysisRequest = true;

    // Submit
    const analyzeBtn = screen.getByRole("button", { name: /Analyze Message/i });
    fireEvent.click(analyzeBtn);

    // Wait for error state
    await waitFor(
      () => {
        expect(screen.getByText(/Analysis Request Failed/i)).toBeInTheDocument();
      },
      { timeout: 2000 }
    );

    // Verify input text is preserved!
    const populatedTextarea = screen.getByLabelText("Message to check") as HTMLTextAreaElement;
    expect(populatedTextarea.value).toContain("URGENT: Dear customer, your electricity");

    // Click Retry
    const retryBtn = screen.getByRole("button", { name: /Retry/i });
    fireEvent.click(retryBtn);

    // Wait for recovery to success
    await waitFor(
      () => {
        expect(screen.getByRole("heading", { name: "High risk" })).toBeInTheDocument();
      },
      { timeout: 2000 }
    );
  });
});
