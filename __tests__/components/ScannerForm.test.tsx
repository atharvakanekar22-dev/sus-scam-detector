import { describe, it, expect, vi } from "vitest";
import { render, screen, fireEvent } from "@testing-library/react";
import { ScannerForm } from "@/components/ScannerForm";

describe("ScannerForm Component", () => {
  it("renders the message field and centered analyze button without sample or counter UI", () => {
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={vi.fn()}
        onReset={vi.fn()}
      />
    );

    expect(screen.getByLabelText("Message to check")).toBeInTheDocument();
    const analyzeButton = screen.getByRole("button", { name: /Analyze Message/i });
    expect(analyzeButton).toBeInTheDocument();
    expect(analyzeButton.parentElement).toHaveClass("justify-center");
    expect(screen.queryByRole("button", { name: "Use sample" })).not.toBeInTheDocument();
    expect(screen.queryByText("Sample message")).not.toBeInTheDocument();
    expect(screen.queryByText(/0 \/ 5,000/)).not.toBeInTheDocument();
    expect(screen.queryByPlaceholderText(/URGENT: Your electricity connection/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Gemini supports English/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/When Gemini is enabled/i)).not.toBeInTheDocument();
  });

  it("conditionally includes validation-msg in aria-describedby only when validation error exists", () => {
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={vi.fn()}
        onReset={vi.fn()}
      />
    );

    const textarea = screen.getByLabelText("Message to check");
    expect(textarea).not.toHaveAttribute("aria-describedby");

    // Trigger validation error via empty spaces submit
    fireEvent.change(textarea, { target: { value: "   " } });
    fireEvent.submit(textarea.closest("form")!);

    expect(textarea.getAttribute("aria-describedby")).toBe("validation-msg");
  });

  it("displays validation error on empty submit", () => {
    const onSubmit = vi.fn();
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={onSubmit}
        onReset={vi.fn()}
      />
    );

    const submitBtn = screen.getByRole("button", { name: /Analyze Message/i });
    // In idle state with empty input, button is disabled
    expect(submitBtn).toBeDisabled();

    // Type spaces only
    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, { target: { value: "   " } });
    fireEvent.submit(textarea.closest("form")!);

    expect(
      screen.getByText(/Please enter or paste a message to inspect/i)
    ).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("displays validation error on short input (< 5 chars)", () => {
    const onSubmit = vi.fn();
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={onSubmit}
        onReset={vi.fn()}
      />
    );

    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, { target: { value: "hi" } });
    fireEvent.submit(textarea.closest("form")!);

    expect(
      screen.getByText(/Please enter at least 5 characters/i)
    ).toBeInTheDocument();
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it("starts over by clearing the message and resetting the analysis", () => {
    const onReset = vi.fn();
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={vi.fn()}
        onReset={onReset}
      />
    );

    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, { target: { value: "Urgent: verify your account now." } });
    fireEvent.click(screen.getByRole("button", { name: "Start over" }));

    expect(textarea).toHaveValue("");
    expect(onReset).toHaveBeenCalledOnce();
  });

  it("shows validation error when text exceeds 5000 characters", () => {
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={vi.fn()}
        onReset={vi.fn()}
      />
    );

    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, { target: { value: "x".repeat(5001) } });
    fireEvent.submit(textarea.closest("form")!);

    expect(
      screen.getByText(/Message exceeds the maximum limit of 5,000 characters/i)
    ).toBeInTheDocument();
  });

  it("invokes onSubmit with the entered message", () => {
    const onSubmit = vi.fn();
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={onSubmit}
        onReset={vi.fn()}
      />
    );

    const textarea = screen.getByLabelText("Message to check");
    fireEvent.change(textarea, { target: { value: "Urgent electricity payment needed." } });

    const submitBtn = screen.getByRole("button", { name: /Analyze Message/i });
    expect(submitBtn).toBeEnabled();
    fireEvent.click(submitBtn);

    expect(onSubmit).toHaveBeenCalledWith("Urgent electricity payment needed.");
  });

  it("displays loading state and disables submission during analysis", () => {
    render(
      <ScannerForm
        status="analyzing"
        errorMessage={null}
        onSubmit={vi.fn()}
        onReset={vi.fn()}
      />
    );

    expect(screen.getByText(/Checking message.../i)).toBeInTheDocument();
    expect(screen.getByLabelText("Message to check")).toBeDisabled();
  });

  it("displays error message and retry button when errorMessage is provided", () => {
    const onSubmit = vi.fn();
    render(
      <ScannerForm
        status="error"
        errorMessage="Network connection timed out"
        onSubmit={onSubmit}
        onReset={vi.fn()}
      />
    );

    expect(screen.getByText(/Analysis Request Failed/i)).toBeInTheDocument();
    expect(screen.getByText(/Network connection timed out/i)).toBeInTheDocument();

    const retryBtn = screen.getByRole("button", { name: /Retry/i });
    expect(retryBtn).toBeInTheDocument();
  });

  it("keeps backend processing details out of the form", () => {
    render(
      <ScannerForm
        status="idle"
        errorMessage={null}
        onSubmit={vi.fn()}
        onReset={vi.fn()}
      />
    );

    expect(
      screen.queryByText(/When Gemini is enabled, your message is sent to Google for analysis/i)
    ).not.toBeInTheDocument();
    expect(
      screen.queryByText(/Gemini supports English/i)
    ).not.toBeInTheDocument();
  });
});
