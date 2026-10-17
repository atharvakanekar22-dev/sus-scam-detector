import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { BrandHeader } from "@/components/BrandHeader";

describe("BrandHeader", () => {
  it("shows SUS as a refreshable home link with a hover and focus tagline", () => {
    render(<BrandHeader />);

    const homeLink = screen.getByRole("link", { name: "SUS home" });
    expect(homeLink).toHaveAttribute("href", "/");
    expect(screen.getByRole("heading", { name: "SUS", level: 1 })).toBeInTheDocument();
    expect(screen.getByText("Scam Message Scanner")).toHaveClass(
      "group-hover:opacity-100",
      "group-focus-visible:opacity-100"
    );
    expect(screen.getByRole("heading", { name: "SUS", level: 1 })).toHaveClass(
      "text-[6rem]",
      "sm:text-[7rem]",
      "transition-transform",
      "group-hover:scale-105"
    );
  });
});
