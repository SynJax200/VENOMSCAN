import type { Metadata } from "next";

import "./globals.css";

export const metadata: Metadata = {
  title: { default: "VENOMSCAN", template: "%s · VENOMSCAN" },
  description:
    "AI-assisted web application security assessments for authorized targets, by S&S Researcher.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="font-sans antialiased">{children}</body>
    </html>
  );
}
