import type { Metadata, Viewport } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-mono-code",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "SUS — Scam Message Scanner",
  description:
    "Check suspicious SMS, WhatsApp messages, and emails for pressure tactics, urgent language, and deceptive patterns.",
  keywords: [
    "scam detector",
    "scam spotter",
    "phishing analysis",
    "SMS fraud",
  ],
  openGraph: {
    title: "SUS — Scam Message Scanner",
    description: "Check suspicious messages for pressure tactics and deceptive patterns.",
    type: "website",
  },
};

export const viewport: Viewport = {
  themeColor: "#F2F7F4",
  width: "device-width",
  initialScale: 1,
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html
      lang="en"
      className={`${inter.variable} ${jetbrainsMono.variable} h-full antialiased`}
    >
      <body className="min-h-full flex flex-col bg-[#F2F7F4] text-[#17312D] font-sans selection:bg-[#D8EFE5] selection:text-[#17312D]">
        {children}
      </body>
    </html>
  );
}
