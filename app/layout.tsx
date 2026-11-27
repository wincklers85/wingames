import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "WinGames · Gestionale",
  description: "Gestione aziendale di acconti, utenti e apparecchi AWP/VLT.",
  manifest: "/manifest.webmanifest",
  icons: {
    icon: "/icon.svg",
    shortcut: "/icon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="it">
      <body className="antialiased">{children}</body>
    </html>
  );
}
