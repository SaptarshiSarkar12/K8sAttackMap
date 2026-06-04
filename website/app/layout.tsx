import type { ReactNode } from 'react';
import type { Metadata } from 'next';
import { RootProvider } from 'fumadocs-ui/provider/next';
import './globals.css';
import Head from "next/head";

export const metadata: Metadata = {
  title: {
    template: '%s | K8sAttackMap',
    default: 'K8sAttackMap — Kubernetes Attack Surface Visualiser',
  },
  description:
    'Ingest a live or offline cluster snapshot, build a directed attack graph across RBAC, workloads, secrets, and nodes, then surface the most dangerous paths, choke points, and actionable remediation — all in a single command.',
  keywords: [
    'kubernetes',
    'security',
    'attack surface',
    'RBAC',
    'CVE',
    'GraalVM',
    'Trivy',
    'k8s',
    'penetration testing',
    'cloud security',
  ],
  authors: [{ name: 'SaptarshiSarkar12' }],
  openGraph: {
    type: 'website',
    title: 'K8sAttackMap',
    description: 'Kubernetes attack surface visualiser and security advisor.',
  },
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning data-scroll-behavior="smooth">
      <Head>
        {/* Preconnect to Google Fonts */}
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Syne:wght@400;500;600;700;800&family=JetBrains+Mono:ital,wght@0,300;0,400;0,500;0,600;0,700;1,400&display=swap"
          rel="stylesheet"
        />
      </Head>
      <body>
        <RootProvider
          theme={{
            defaultTheme: 'dark',
            enabled: true,
          }}
        >
          {children}
        </RootProvider>
      </body>
    </html>
  );
}
