"use client";

import { useState } from "react";
import { BrandHeader } from "@/components/BrandHeader";
import { ScannerForm } from "@/components/ScannerForm";
import { ResultsPanel } from "@/components/ResultsPanel";
import { AnalysisResult, ScanStatus } from "@/lib/types";
import { AnalyzeResponse } from "@/lib/schemas";

export default function Home() {
  const [status, setStatus] = useState<ScanStatus>("idle");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const handleAnalyze = async (message: string) => {
    setStatus("analyzing");
    setErrorMessage(null);

    try {
      const response = await fetch("/api/analyze", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ message }),
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data?.error?.message || "Analysis request failed.");
      }

      const engineResponse = data as AnalyzeResponse;

      const adaptedResult: AnalysisResult = {
        id: engineResponse.id,
        timestamp: engineResponse.timestamp,
        riskLevel: engineResponse.riskLevel,
        riskScorePercent: engineResponse.heuristicScore,
        summary: engineResponse.summary,
        findings: engineResponse.findings.map((f) => ({
          id: f.id,
          category: f.category,
          ruleId: f.ruleId,
          title: f.title,
          description: f.description,
          highlightedText: f.span.text,
          span: f.span,
          severity: f.severity,
        })),
        recommendedSteps: engineResponse.recommendedSteps,
        isMock: false,
        rawMessage: message,
        analyzedUrls: engineResponse.analyzedUrls,
        metadata: {
          ...engineResponse.metadata,
          analysisMode: engineResponse.metadata.analysisMode,
        },
      };

      setResult(adaptedResult);
      setStatus("success");
    } catch (err: unknown) {
      setStatus("error");
      if (err instanceof TypeError && err.message.toLowerCase().includes("fetch")) {
        setErrorMessage(
          "Cannot reach the analysis server. Make sure the app is running with npm run dev, then try again."
        );
      } else if (err instanceof Error) {
        setErrorMessage(err.message);
      } else {
        setErrorMessage("An unexpected error occurred during message inspection.");
      }
    }
  };

  const handleReset = () => {
    setStatus("idle");
    setResult(null);
    setErrorMessage(null);
  };

  return (
    <div className="min-h-screen bg-transparent text-[#17312D] selection:bg-[#D8EFE5]">
      {/* Top Navigation Anchor / Skip Link for A11y */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:px-4 focus:py-2 focus:bg-[#177D69] focus:text-white focus:rounded-md focus:shadow-md"
      >
        Skip to main content
      </a>

      <div className="mx-auto flex min-h-screen w-full max-w-[820px] flex-1 flex-col px-4 sm:px-6">
        <BrandHeader />

        <main
          id="main-content"
          className="flex-1 space-y-7 pb-14 pt-4 sm:space-y-8 sm:pt-6"
          tabIndex={-1}
        >
          <section
            aria-label="Message Input Section"
            className="rounded-3xl border border-[#D9E7E1] bg-white p-5 shadow-[0_24px_70px_-38px_rgba(22,62,52,0.3)] sm:p-8"
          >
            <ScannerForm
              status={status}
              errorMessage={errorMessage}
              onSubmit={handleAnalyze}
              onReset={handleReset}
            />
          </section>

          {status === "success" && result && (
            <div id="results-anchor" className="transition-all duration-300">
              <ResultsPanel result={result} onReset={handleReset} />
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
