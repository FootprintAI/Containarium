import type { Metadata } from "next";
import "./globals.css";

// Public origin used to resolve absolute URLs in social-preview tags.
// Override per deployment with NEXT_PUBLIC_SITE_URL; defaults to the
// project's canonical site. (The dashboard ships under basePath /webui,
// so the bundled card lives at <origin>/webui/og-image.png.)
const siteUrl = process.env.NEXT_PUBLIC_SITE_URL ?? "https://containarium.dev";
const ogImage = "/webui/og-image.png";

const title = "Containarium — self-hostable container & agent platform";
const description =
  "Self-hostable, MCP-native container sandboxes for AI agents. Own your GPU. Apache-2.0.";

export const metadata: Metadata = {
  metadataBase: new URL(siteUrl),
  title,
  description,
  // Open Graph — the rich link-preview card shown on Slack, LinkedIn,
  // Facebook, Discord, etc. when a Containarium URL is shared.
  openGraph: {
    title,
    description,
    url: siteUrl,
    siteName: "Containarium",
    type: "website",
    images: [
      {
        url: ogImage, // resolved against metadataBase → absolute URL
        width: 1200,
        height: 630,
        alt: "Containarium — self-hostable container & agent platform",
      },
    ],
  },
  // Twitter/X card — summary_large_image renders the 1200×630 image full-width.
  twitter: {
    card: "summary_large_image",
    title,
    description,
    images: [ogImage],
  },
};

// Runs synchronously before React hydrates — prevents flash of wrong theme.
const themeScript = `(function(){var t=localStorage.getItem('theme')||'dark';if(t==='light')document.documentElement.classList.add('light');})();`;

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>{children}</body>
    </html>
  );
}
