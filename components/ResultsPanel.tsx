"use client";

import React, { useState } from "react";
import { AnalysisResult, SignalFinding } from "@/lib/types";

interface ResultsPanelProps {
  result: AnalysisResult;
  onReset: () => void;
}

function formatAssessmentSummary(result: AnalysisResult): string {
  const riskTitle =
    result.riskLevel === "high"
      ? "HIGH RISK"
      : result.riskLevel === "medium"
        ? "BE CAREFUL"
        : "LOW RISK";
  return [
    `SUS result: ${riskTitle} (Rule score: ${result.riskScorePercent}/100)`,
    "",
    "Summary:",
    result.summary,
    "",
    "Recommended Actions:",
    ...result.recommendedSteps.map((step) => `• ${step.text}`),
  ].join("\n");
}

function renderHighlightedMessage(
  rawMessage: string,
  findings: SignalFinding[]
): React.ReactNode {
  const validSpans = findings
    .filter(
      (finding): finding is SignalFinding & { span: NonNullable<SignalFinding["span"]> } =>
        Boolean(
          finding.span &&
            finding.span.start >= 0 &&
            finding.span.end <= rawMessage.length &&
            finding.span.start < finding.span.end
        )
    )
    .map((finding) => ({
      start: finding.span.start,
      end: finding.span.end,
      severity: finding.severity,
      title: finding.title,
    }))
    .sort((a, b) => a.start - b.start);

  if (validSpans.length === 0) return rawMessage;

  const elements: React.ReactNode[] = [];
  let cursor = 0;

  validSpans.forEach((span, index) => {
    const start = Math.max(span.start, cursor);
    if (span.end <= cursor) return;
    if (start > cursor) {
      elements.push(<span key={`text-${cursor}`}>{rawMessage.slice(cursor, start)}</span>);
    }

    const highlightColor =
      span.severity === "high"
        ? "bg-[#FDE8E6] text-[#8E2F29]"
        : span.severity === "medium"
          ? "bg-[#FFF3D7] text-[#76500F]"
          : "bg-[#E8F5EF] text-[#176246]";
    elements.push(
      <mark
        key={`highlight-${index}-${start}`}
        title={span.title}
        className={`rounded px-0.5 ${highlightColor}`}
      >
        <span className="sr-only">Flagged evidence: </span>
        {rawMessage.slice(start, span.end)}
      </mark>
    );
    cursor = span.end;
  });

  if (cursor < rawMessage.length) {
    elements.push(<span key="text-end">{rawMessage.slice(cursor)}</span>);
  }
  return elements;
}

const SIGNAL_LABELS: Record<string, string> = {
  credential_theft: "Asks for private codes or details",
  urgency_coercion: "Pressures you to act quickly",
  financial_pressure: "Unexpected money or bill claim",
  suspicious_link: "Contains a suspicious link",
  impersonation: "Unverified contact details",
  security_advisory: "Safety warning",
  urgency: "Pressures you to act quickly",
  personal_data: "Asks for private codes or details",
};

export function ResultsPanel({ result, onReset }: ResultsPanelProps) {
  const { riskLevel, findings } = result;
  const [copyStatus, setCopyStatus] = useState<"idle" | "copied" | "error">("idle");
  const signalGroups = findings.reduce<Array<{ label: string; evidence: string[] }>>(
    (groups, item) => {
      const label = SIGNAL_LABELS[item.category] || item.title;
      const evidence = item.highlightedText || item.span?.text;
      const group = groups.find((entry) => entry.label === label);
      if (group) {
        if (
          evidence &&
          !group.evidence.some(
            (existing) => existing.includes(evidence) || evidence.includes(existing)
          )
        ) {
          group.evidence.push(evidence);
        }
      } else {
        groups.push({ label, evidence: evidence ? [evidence] : [] });
      }
      return groups;
    },
    []
  );

  const riskDisplay = {
    high: {
      label: "High risk",
      color: "#991B1B",
      meaning: "This message may be a scam.",
      recommendation:
        "Do not click or reply. Check with the company using its official app or number.",
    },
    medium: {
      label: "Check carefully",
      color: "#DC2626",
      meaning: "This message has warning signs.",
      recommendation:
        "Do not click links or share details until you verify the message.",
    },
    low: {
      label: "No common warning signs",
      color: "#27805A",
      meaning: "No common scam signs were found.",
      recommendation:
        "Confirm requests for money or personal details directly with the sender.",
    },
  }[riskLevel];
  const score = Math.max(0, Math.min(100, result.riskScorePercent));
  const gaugeLength = Math.PI * 88;

  const handleCopySummary = async () => {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error("Clipboard API unavailable");
      }
      await navigator.clipboard.writeText(formatAssessmentSummary(result));
      setCopyStatus("copied");
      setTimeout(() => setCopyStatus("idle"), 3000);
    } catch {
      setCopyStatus("error");
      setTimeout(() => setCopyStatus("idle"), 4000);
    }
  };

  return (
    <section
      aria-label="Analysis Results"
      aria-live="polite"
      className="space-y-6 rounded-3xl border border-[#D9E7E1] bg-white p-5 shadow-[0_16px_48px_-36px_rgba(22,62,52,0.28)] sm:p-8"
    >
      <div className="flex flex-col gap-5 border-b border-[#E7EEEA] pb-5 sm:flex-row sm:items-center">
        <div
          className="relative mx-auto h-[5.75rem] w-44 shrink-0 sm:mx-0"
          role="img"
          aria-label={`${riskDisplay.label}; rule score ${score} out of 100`}
        >
          <svg viewBox="0 0 200 110" className="h-full w-full" aria-hidden="true">
            <path
              d="M 12 100 A 88 88 0 0 1 188 100"
              fill="none"
              stroke="#E7EEEA"
              strokeWidth="14"
              strokeLinecap="round"
            />
            <path
              d="M 12 100 A 88 88 0 0 1 188 100"
              fill="none"
              stroke={riskDisplay.color}
              strokeWidth="14"
              strokeLinecap="round"
              strokeDasharray={gaugeLength}
              strokeDashoffset={gaugeLength * (1 - score / 100)}
            />
          </svg>
          <span
            className="absolute inset-x-0 bottom-0 text-center text-3xl font-bold tracking-tight"
            style={{ color: riskDisplay.color }}
          >
            {score}
            <span className="ml-0.5 text-sm font-medium text-[#647873]">/100</span>
          </span>
        </div>
        <div className="min-w-0 flex-1 text-center sm:text-left">
          <h2 className="mt-1 text-2xl font-semibold tracking-tight text-[#17312D]">
            {riskDisplay.label}
          </h2>
          <p className="mt-1 text-xs font-medium text-[#647873]">Rule score</p>
          <p className="mt-2 text-sm leading-relaxed text-[#52645E]">{riskDisplay.meaning}</p>
          <p className="mt-1 text-xs text-[#647873]">
            Based on warning signs found, not a probability.
          </p>
          {riskLevel === "low" && (
            <p className="mt-1 text-xs text-[#647873]">This does not prove it is safe.</p>
          )}
        </div>
      </div>

      <div className="space-y-3">
        <h2 className="text-base font-semibold text-[#17312D]">Warning signs</h2>
        {signalGroups.length > 0 ? (
          <ul className="space-y-2">
            {signalGroups.map((group) => (
              <li key={group.label} className="flex items-start gap-2.5 text-sm text-[#344A43]">
                <span
                  className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full"
                  style={{ backgroundColor: riskDisplay.color }}
                  aria-hidden="true"
                />
                <span>
                  {group.label}
                  {group.evidence.length > 0 && (
                    <span className="ml-1 text-[#647873]">
                      (&ldquo;{group.evidence.join("”, “")}&rdquo;)
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-[#52645E]">No common scam signs were found.</p>
        )}
      </div>

      <div className="rounded-2xl border border-[#D9E7E1] bg-[#F7FAF8] p-4 sm:p-5">
        <h2 className="text-base font-semibold text-[#17312D]">What to do</h2>
        <p className="mt-1.5 text-sm leading-relaxed text-[#344A43]">
          {riskDisplay.recommendation}
        </p>
      </div>

      {result.rawMessage && (
        <details className="group rounded-xl border border-[#E7EEEA] px-4 py-3">
          <summary className="cursor-pointer text-sm font-medium text-[#34524C] marker:text-[#647873]">
            See checked message
          </summary>
          <div className="mt-3 space-y-2">
            <p className="text-xs text-[#647873]">Flagged text is highlighted.</p>
            <div className="rounded-lg bg-[#F7FAF8] p-3 text-xs leading-relaxed text-[#17312D] whitespace-pre-wrap break-words">
              {renderHighlightedMessage(result.rawMessage, findings)}
            </div>
          </div>
        </details>
      )}

      <div className="flex flex-wrap items-center gap-2 border-t border-[#E7EEEA] pt-4">
        <button
          type="button"
          onClick={handleCopySummary}
          aria-label="Copy assessment summary to clipboard"
          className="rounded-lg border border-[#D9E7E1] bg-white px-3 py-1.5 text-xs font-medium text-[#17312D] transition-colors hover:bg-[#F2F7F4] focus-ring"
        >
          {copyStatus === "copied"
            ? "Summary copied"
            : copyStatus === "error"
              ? "Unable to copy"
              : "Copy summary"}
        </button>
        <button
          type="button"
          onClick={onReset}
          className="rounded-lg border border-[#D9E7E1] bg-[#F2F7F4] px-3 py-1.5 text-xs font-medium text-[#17312D] transition-colors hover:bg-[#D9E7E1]/40 focus-ring"
        >
          Check another message
        </button>
      </div>

      <div className="sr-only" aria-live="polite" aria-atomic="true">
        {copyStatus === "copied" && "Assessment summary copied to clipboard."}
        {copyStatus === "error" && "Unable to copy assessment summary to clipboard."}
      </div>
    </section>
  );
}
