import { NextRequest, NextResponse } from "next/server";
import { AnalyzeRequestSchema, AnalyzeResponseSchema } from "@/lib/schemas";
import { analyzeMessage } from "@/lib/analyzer/engine";
import {
  analyzeWithGemini,
  GeminiProviderError,
  mergeGeminiAssessment,
} from "@/lib/analyzer/gemini";

export async function POST(request: NextRequest) {
  try {
    let body: unknown;
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        {
          error: {
            code: "INVALID_INPUT",
            message: "Invalid JSON request body.",
          },
        },
        { status: 400 }
      );
    }

    // Support simulated error testing for reviewers in development/test environments only
    const isDevelopmentOrTest = process.env.NODE_ENV !== "production";
    if (
      isDevelopmentOrTest &&
      typeof body === "object" &&
      body !== null &&
      (body as { forceError?: boolean }).forceError === true
    ) {
      return NextResponse.json(
        {
          error: {
            code: "INTERNAL_ERROR",
            message: "Simulated analysis server exception for reviewer error testing.",
          },
        },
        { status: 500 }
      );
    }

    // Validate request body using Zod
    const parseResult = AnalyzeRequestSchema.safeParse(body);
    if (!parseResult.success) {
      const firstIssue = parseResult.error.issues[0];
      return NextResponse.json(
        {
          error: {
            code: "INVALID_INPUT",
            message: firstIssue ? firstIssue.message : "Validation failed for submitted message.",
            details: parseResult.error.flatten(),
          },
        },
        { status: 400 }
      );
    }

    const analysisStartedAt = performance.now();
    const message = parseResult.data.message;
    let analysisResult = analyzeMessage(message);

    if (process.env.GEMINI_API_KEY) {
      try {
        const geminiAssessment = await analyzeWithGemini(message);
        analysisResult = mergeGeminiAssessment(
          message,
          analysisResult,
          geminiAssessment
        );
      } catch (err: unknown) {
        if (!(err instanceof GeminiProviderError)) {
          throw err;
        }

        analysisResult = {
          ...analysisResult,
          metadata: {
            ...analysisResult.metadata,
            analysisNotice: err.message,
          },
        };
      }
    } else {
      analysisResult = {
        ...analysisResult,
        metadata: {
          ...analysisResult.metadata,
          analysisNotice:
            "Enhanced analysis is not configured. Showing rule-based results.",
        },
      };
    }

    analysisResult = {
      ...analysisResult,
      metadata: {
        ...analysisResult.metadata,
        executionTimeMs:
          Math.round((performance.now() - analysisStartedAt) * 100) / 100,
      },
    };

    // Validate output structure against response schema before sending
    const validatedOutput = AnalyzeResponseSchema.parse(analysisResult);

    return NextResponse.json(validatedOutput, { status: 200 });
  } catch (err: unknown) {
    const isDevelopmentOrTest = process.env.NODE_ENV !== "production";
    return NextResponse.json(
      {
        error: {
          code: "INTERNAL_ERROR",
          message: "An unexpected error occurred during message inspection.",
          details: isDevelopmentOrTest && err instanceof Error ? err.message : undefined,
        },
      },
      { status: 500 }
    );
  }
}
