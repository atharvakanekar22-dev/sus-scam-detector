import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { ResultsPanel } from "@/components/ResultsPanel";
import { MOCK_HIGH_RISK_RESULT, MOCK_MEDIUM_RISK_RESULT, MOCK_LOW_RISK_RESULT } from "@/lib/mock-data";

describe("ResultsPanel Component", () => {
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

  it("shows a clear high-risk result, simple warning signs, and a separate recommendation", () => {
    const onReset = vi.fn();
    render(<ResultsPanel result={MOCK_HIGH_RISK_RESULT} onReset={onReset} />);

    expect(screen.getByRole("heading", { name: "High risk" })).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: "High risk, rule score 88 out of 100" })
    ).toBeInTheDocument();
    expect(screen.getByText(/Score shows matched warning signs, not certainty/i)).toBeInTheDocument();
    expect(screen.getByText(/Pressures you to act quickly/i)).toBeInTheDocument();
    expect(screen.getByText(/Contains a suspicious link/i)).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "What to do" })).toBeInTheDocument();
    expect(screen.getByText(/Do not reply or click links/i)).toBeInTheDocument();
    expect(screen.queryByText(/Phase 1 UI Demonstration/i)).not.toBeInTheDocument();

    const resetBtn = screen.getByRole("button", { name: /Check another message/i });
    fireEvent.click(resetBtn);
    expect(onReset).toHaveBeenCalledTimes(1);
  });

  it("shows the medium-risk color gauge and plain-language result", () => {
    render(<ResultsPanel result={MOCK_MEDIUM_RISK_RESULT} onReset={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "Be careful" })).toBeInTheDocument();
    expect(
      screen.getByRole("img", { name: "Be careful, rule score 58 out of 100" })
    ).toBeInTheDocument();
    expect(screen.getByText(/Asks for private codes or details/i)).toBeInTheDocument();
  });

  it("renders low risk badge for benign result", () => {
    render(<ResultsPanel result={MOCK_LOW_RISK_RESULT} onReset={vi.fn()} />);

    expect(screen.getByRole("heading", { name: "No common warning signs" })).toBeInTheDocument();
    expect(
      screen.getByText(/This does not prove the message is genuine/i)
    ).toBeInTheDocument();
  });

  it("keeps the analysis provider out of the results interface", () => {
    const result = {
      ...MOCK_HIGH_RISK_RESULT,
      metadata: {
        charCount: 76,
        executionTimeMs: 42,
        isHeuristic: true,
        analysisMode: "gemini" as const,
      },
    };

    render(<ResultsPanel result={result} onReset={vi.fn()} />);

    expect(screen.getByText(/Score shows matched warning signs, not certainty/i)).toBeInTheDocument();
    expect(screen.queryByText(/Gemini/i)).not.toBeInTheDocument();
  });

  it("renders accessible evidence highlights with screen-reader cues while preserving raw text", () => {
    const resultWithEvidence = {
      ...MOCK_HIGH_RISK_RESULT,
      rawMessage: "Your power will be disconnected tonight at 9:30 PM immediately.",
      findings: [
        {
          id: "f-1",
          category: "urgency",
          ruleId: "URG-01",
          title: "Immediate Threat",
          description: "Urgent shutoff threat",
          severity: "high" as const,
          span: {
            start: 19,
            end: 51,
            text: "disconnected tonight at 9:30 PM",
          },
        },
      ],
    };

    render(<ResultsPanel result={resultWithEvidence} onReset={vi.fn()} />);

    // Screen-reader helper inside mark element
    const srFlagged = screen.getByText(/Flagged evidence:/i);
    expect(srFlagged).toBeInTheDocument();
    expect(srFlagged).toHaveClass("sr-only");

    // Message text is fully preserved
    expect(screen.getByText(/Your power will be/i)).toBeInTheDocument();
    expect(screen.getByText(/immediately\./i)).toBeInTheDocument();
  });

  it("copies assessment summary without including raw message by default", async () => {
    const resultToCopy = {
      ...MOCK_HIGH_RISK_RESULT,
      rawMessage: "CONFIDENTIAL_SENSITIVE_TEXT_NOT_TO_BE_COPIED_BY_DEFAULT",
    };

    render(<ResultsPanel result={resultToCopy} onReset={vi.fn()} />);

    const copyBtn = screen.getByRole("button", { name: /Copy assessment summary to clipboard/i });
    fireEvent.click(copyBtn);

    await waitFor(() => {
      expect(writeTextMock).toHaveBeenCalledTimes(1);
    });

    const copiedContent: string = writeTextMock.mock.calls[0][0];

    // Verify included fields
    expect(copiedContent).toContain("SUS Scam Risk Assessment: HIGH RISK (88% Rule Score)");
    expect(copiedContent).toContain("Summary:");
    expect(copiedContent).toContain(MOCK_HIGH_RISK_RESULT.summary);
    expect(copiedContent).not.toContain("Disclaimer:");

    // Verify raw message is EXCLUDED
    expect(copiedContent).not.toContain("CONFIDENTIAL_SENSITIVE_TEXT_NOT_TO_BE_COPIED_BY_DEFAULT");

    // Verify UI success feedback and live announcement
    expect(screen.getAllByText(/Summary copied/i).length).toBeGreaterThan(0);
    expect(screen.getByText(/Assessment summary copied to clipboard\./i)).toBeInTheDocument();
  });

  it("handles clipboard failure gracefully", async () => {
    writeTextMock.mockRejectedValueOnce(new Error("Permission denied"));

    render(<ResultsPanel result={MOCK_HIGH_RISK_RESULT} onReset={vi.fn()} />);

    const copyBtn = screen.getByRole("button", { name: /Copy assessment summary to clipboard/i });
    fireEvent.click(copyBtn);

    await waitFor(() => {
      expect(screen.getByText("Unable to copy")).toBeInTheDocument();
    });

    expect(screen.getByText("Unable to copy assessment summary to clipboard.")).toBeInTheDocument();
  });
});
