import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ResultsPanel } from "@/components/ResultsPanel";
import { AnalysisResult } from "@/lib/types";

describe("ResultsPanel Link Intelligence Display", () => {
  let writeTextMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    writeTextMock = vi.fn().mockResolvedValue(undefined);
    Object.assign(navigator, {
      clipboard: {
        writeText: writeTextMock,
      },
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders defanged hostnames, indicators, and brand check results for analyzed URLs", async () => {
    const mockResult: AnalysisResult = {
      id: "test-url-res-01",
      timestamp: new Date().toISOString(),
      riskLevel: "high",
      riskScorePercent: 85,
      summary: "This message contains a deceptive brand impersonation link.",
      findings: [
        {
          id: "f-1",
          category: "impersonation",
          title: "Deceptive Brand Impersonation Domain",
          description: "Domain mimics State Bank of India.",
          severity: "high",
          span: { start: 10, end: 42, text: "https://sbi-kyc-verify-portal.in" },
        },
      ],
      recommendedSteps: [
        { id: "s-1", text: "Do not open unverified links or enter credentials." },
      ],
      isMock: false,
      rawMessage: "Visit now https://sbi-kyc-verify-portal.in to update.",
      analyzedUrls: [
        {
          originalUrl: "https://sbi-kyc-verify-portal.in",
          normalizedUrl: "https://sbi-kyc-verify-portal.in",
          hostname: "sbi-kyc-verify-portal.in",
          protocol: "https",
          isSuspicious: true,
          threatLevel: "high",
          indicators: [
            {
              code: "BRAND_LOOKALIKE",
              title: "Possible Brand Impersonation",
              description: "The domain appears to imitate State Bank of India.",
              severity: "high",
            },
          ],
          brandCheck: {
            claimedBrand: "State Bank of India",
            isOfficialDomain: false,
            isLookalike: true,
            confidence: "likely",
            explanation: "The domain 'sbi-kyc-verify-portal.in' appears to imitate State Bank of India, but does not match its official domain (sbi.co.in).",
          },
          span: { start: 10, end: 42, text: "https://sbi-kyc-verify-portal.in" },
        },
      ],
    };

    render(<ResultsPanel result={mockResult} onReset={vi.fn()} />);

    // Check heading for links in message
    expect(screen.getByRole("heading", { name: /Links in message \(1\)/i })).toBeInTheDocument();

    // Check that hostname is rendered as text
    expect(screen.getByText("sbi-kyc-verify-portal.in")).toBeInTheDocument();

    // Check badge
    expect(screen.getByText("High risk link")).toBeInTheDocument();

    // Check brand warning
    expect(screen.getAllByText(/Possible brand impersonation/i)[0]).toBeInTheDocument();
    expect(screen.getByText(/does not match its official domain/i)).toBeInTheDocument();

    // Check heuristic notice
    expect(screen.getByText(/Analysis based on local heuristic inspection/i)).toBeInTheDocument();

    // Check copy summary includes links
    const copyBtn = screen.getByRole("button", { name: /Copy assessment summary to clipboard/i });
    fireEvent.click(copyBtn);
    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledTimes(1);
    });
    expect(writeTextMock.mock.calls[0][0]).toContain("sbi-kyc-verify-portal.in");
  });

  it("renders a clear note when no links are present in the message", () => {
    const mockNoLinks: AnalysisResult = {
      id: "test-url-res-02",
      timestamp: new Date().toISOString(),
      riskLevel: "low",
      riskScorePercent: 0,
      summary: "No common scam signs were found.",
      findings: [],
      recommendedSteps: [{ id: "s-1", text: "Exercise standard digital caution." }],
      isMock: false,
      rawMessage: "Hey friend, are you free this afternoon?",
      analyzedUrls: [],
    };

    render(<ResultsPanel result={mockNoLinks} onReset={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "Links in message" })).toBeInTheDocument();
    expect(screen.getByText(/No links were detected in this message/i)).toBeInTheDocument();
  });
});
