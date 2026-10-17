"use client";

import React, { useState } from "react";
import { ScanStatus } from "@/lib/types";

interface ScannerFormProps {
  status: ScanStatus;
  errorMessage: string | null;
  onSubmit: (message: string) => void;
  onReset: () => void;
}

const MAX_CHAR_COUNT = 5000;
const MIN_CHAR_COUNT = 5;

export function ScannerForm({
  status,
  errorMessage,
  onSubmit,
  onReset,
}: ScannerFormProps) {
  const [inputText, setInputText] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);

  const charCount = inputText.length;
  const isOverLimit = charCount > MAX_CHAR_COUNT;
  const isAnalyzing = status === "analyzing";

  const handleTextChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInputText(e.target.value);
    if (validationError) {
      setValidationError(null);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();

    // Check empty or whitespace only
    if (!inputText || inputText.trim().length === 0) {
      setValidationError("Please enter or paste a message to inspect.");
      return;
    }

    if (inputText.trim().length < MIN_CHAR_COUNT) {
      setValidationError(`Please enter at least ${MIN_CHAR_COUNT} characters for meaningful analysis.`);
      return;
    }

    if (isOverLimit) {
      setValidationError(`Message exceeds the maximum limit of ${MAX_CHAR_COUNT.toLocaleString()} characters.`);
      return;
    }

    setValidationError(null);
    onSubmit(inputText.trim());
  };

  const handleClear = () => {
    setInputText("");
    setValidationError(null);
    onReset();
  };

  return (
    <form onSubmit={handleSubmit} className="space-y-4" noValidate>
      <div className="flex items-center justify-between">
        <label
          htmlFor="message-input"
          className="text-sm font-medium text-[#17312D]"
        >
          Message to check
        </label>
        {inputText && (
          <button
            type="button"
            onClick={handleClear}
            disabled={isAnalyzing}
            className="text-xs text-[#647873] hover:text-[#17312D] underline underline-offset-2 transition-colors disabled:opacity-50 cursor-pointer"
          >
            Start over
          </button>
        )}
      </div>

      {/* Textarea Field */}
      <div className="space-y-1.5">
        <div className="relative">
          <textarea
            id="message-input"
            name="message-input"
            rows={5}
            value={inputText}
            onChange={handleTextChange}
            disabled={isAnalyzing}
            aria-invalid={Boolean(validationError || isOverLimit)}
            aria-describedby={validationError ? "validation-msg" : undefined}
            className={`w-full min-h-[150px] resize-y rounded-2xl border bg-[#FBFDFC] p-4 text-sm leading-relaxed text-[#17312D] transition-colors focus-ring disabled:bg-[#F2F7F4] disabled:opacity-75 sm:p-5 ${
              validationError || isOverLimit
                ? "border-[#FACBC4] focus-visible:border-[#962526] focus-visible:ring-[#FACBC4]"
                : "border-[#D9E7E1]"
            }`}
          />
        </div>

      </div>

      {/* Validation or Error Alert */}
      {validationError && (
        <div
          id="validation-msg"
          role="alert"
          className="p-3 rounded-lg bg-[#FDF1EF] border border-[#FACBC4] text-xs text-[#962526] flex items-center gap-2"
        >
          <svg
            className="w-4 h-4 shrink-0"
            fill="none"
            stroke="currentColor"
            viewBox="0 0 24 24"
            aria-hidden="true"
          >
            <path
              strokeLinecap="round"
              strokeLinejoin="round"
              strokeWidth="2"
              d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
            />
          </svg>
          <span>{validationError}</span>
        </div>
      )}

      {errorMessage && !validationError && (
        <div
          role="alert"
          className="p-3.5 rounded-xl bg-[#FDF1EF] border border-[#FACBC4] text-xs text-[#962526] flex items-start justify-between gap-3"
        >
          <div className="flex items-start gap-2">
            <svg
              className="w-4 h-4 mt-0.5 shrink-0"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
              aria-hidden="true"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth="2"
                d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"
              />
            </svg>
            <div>
              <p className="font-semibold text-sm">Analysis Request Failed</p>
              <p className="mt-0.5 leading-relaxed">{errorMessage}</p>
            </div>
          </div>
          <button
            type="button"
            onClick={handleSubmit}
            className="px-2.5 py-1 text-xs font-medium rounded-md bg-[#FFFFFF] border border-[#FACBC4] text-[#962526] hover:bg-[#FACBC4]/30 focus-ring cursor-pointer"
          >
            Retry
          </button>
        </div>
      )}

      {/* Form Submission Controls */}
      <div className="flex justify-center pt-1">
        {/* Action Button */}
        <button
          type="submit"
          disabled={isAnalyzing || isOverLimit || inputText.trim().length === 0}
          aria-busy={isAnalyzing}
          className="inline-flex items-center justify-center gap-2 px-5 py-2.5 text-sm font-medium rounded-xl text-white bg-[#0F6B5A] hover:bg-[#0B584B] active:scale-[0.98] transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:active:scale-100 focus-ring cursor-pointer"
        >
          {isAnalyzing ? (
            <>
              {/* CSS spinner */}
              <svg
                className="w-4 h-4 animate-spin text-white"
                fill="none"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <circle
                  className="opacity-25"
                  cx="12"
                  cy="12"
                  r="10"
                  stroke="currentColor"
                  strokeWidth="4"
                />
                <path
                  className="opacity-75"
                  fill="currentColor"
                  d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
                />
              </svg>
              <span>Checking message...</span>
            </>
          ) : (
            <>
              <span>Analyze Message</span>
              <svg
                className="w-4 h-4"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
                aria-hidden="true"
              >
                <path
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  strokeWidth="2"
                  d="M14 5l7 7m0 0l-7 7m7-7H3"
                />
              </svg>
            </>
          )}
        </button>
      </div>
    </form>
  );
}
