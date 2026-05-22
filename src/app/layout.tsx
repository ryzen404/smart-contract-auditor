import type { Metadata } from 'next';
import './globals.css';

export const metadata: Metadata = {
  title: 'SmartContract AI Auditor',
  description: 'Multi-agent AI smart contract security audit platform',
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body style={{ background: '#0a0a0f', minHeight: '100vh' }}>
        {children}
      </body>
    </html>
  );
}
