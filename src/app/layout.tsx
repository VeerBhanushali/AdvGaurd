import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'AdGuard Web - Cloud DNS-over-HTTPS AdBlock Engine',
  description: 'Self-hosted DNS-over-HTTPS privacy engine & rule converter for web hosting, Vercel, and Hostinger',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className="dark">
      <body className="min-h-screen bg-[#080c14] text-slate-100 antialiased selection:bg-emerald-500 selection:text-black">
        {children}
      </body>
    </html>
  );
}

