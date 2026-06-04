'use client';

import Link from 'next/link';
import {
    Shield,
    Terminal,
    Command,
    LayoutGrid,
    Download,
    CheckCircle2,
    ArrowRight
} from 'lucide-react';

const VERSION = 'v1.0.0';
const REPO_BASE = 'https://github.com/SaptarshiSarkar12/K8sAttackMap/releases/download';

// ─── Navbar (Matches your page.tsx) ──────────────────────────────────────────
function Navbar() {
    return (
        <nav className="fixed top-0 left-0 right-0 z-50 border-b border-slate-800/60 bg-surface-900/90 backdrop-blur-md">
            <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
                <Link href="/" className="flex items-center gap-2.5">
                    <Shield size={20} className="text-attack" />
                    <span className="font-bold text-slate-100 text-sm tracking-wide" style={{ fontFamily: 'Syne, sans-serif' }}>
            K8sAttackMap
          </span>
                </Link>
                <div className="flex items-center gap-1 sm:gap-2">
                    <Link href="/docs" className="text-xs sm:text-sm text-slate-400 hover:text-slate-200 px-2 sm:px-3 py-1.5 rounded-md transition-colors">
                        Docs
                    </Link>
                    <Link href="/download" className="text-xs sm:text-sm text-safe hover:text-safe/80 px-2 sm:px-3 py-1.5 rounded-md transition-colors font-medium">
                        Download
                    </Link>
                    <a href="https://github.com/SaptarshiSarkar12/K8sAttackMap" target="_blank" rel="noopener noreferrer" className="flex items-center gap-1.5 text-xs sm:text-sm text-slate-400 hover:text-slate-200 px-2 sm:px-3 py-1.5 rounded-md border border-slate-700 hover:border-safe/40 transition-all">
                        GitHub
                    </a>
                </div>
            </div>
        </nav>
    );
}

// ─── Footer (Matches your page.tsx) ──────────────────────────────────────────
function Footer() {
    return (
        <footer className="border-t border-slate-800 py-10 px-4 mt-20">
            <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-600">
                <div className="flex items-center gap-2">
                    <Shield size={14} className="text-attack/60" />
                    <span>K8sAttackMap · Apache License 2.0</span>
                </div>
                <div className="flex items-center gap-4">
                    <Link href="/docs" className="hover:text-slate-400 transition-colors">Documentation</Link>
                    <a href="https://github.com/SaptarshiSarkar12/K8sAttackMap" target="_blank" rel="noopener noreferrer" className="hover:text-slate-400 transition-colors">GitHub</a>
                </div>
            </div>
        </footer>
    );
}

// ─── Download Page Content ───────────────────────────────────────────────────
export default function DownloadPage() {
    const platforms = [
        {
            id: 'linux',
            title: 'Linux',
            icon: <Terminal size={24} className="text-node" />,
            borderColor: 'border-node/30 hover:border-node',
            shadowColor: 'hover:shadow-node/10',
            description: 'Compiled statically for Linux distributions.',
            artifacts: [
                { label: 'Linux x86_64', file: `K8sAttackMap-${VERSION}-linux-x86_64` },
                { label: 'Linux ARM64', file: `K8sAttackMap-${VERSION}-linux-arm64` }
            ]
        },
        {
            id: 'macos',
            title: 'macOS',
            icon: <Command size={24} className="text-safe" />,
            borderColor: 'border-safe/30 hover:border-safe',
            shadowColor: 'hover:shadow-safe/10',
            description: 'Native Apple Silicon performance.',
            artifacts: [
                { label: 'macOS ARM64', file: `K8sAttackMap-${VERSION}-macos-arm64` }
            ]
        },
        {
            id: 'windows',
            title: 'Windows',
            icon: <LayoutGrid size={24} className="text-purple-400" />,
            borderColor: 'border-purple-400/30 hover:border-purple-400',
            shadowColor: 'hover:shadow-purple-400/10',
            description: 'Standalone Windows executable.',
            artifacts: [
                { label: 'Windows x86_64', file: `K8sAttackMap-${VERSION}-windows-x86_64.exe` }
            ]
        }
    ];

    return (
        <div className="min-h-screen bg-surface-900">
            <Navbar />

            <main className="pt-28 px-4 max-w-5xl mx-auto">
                {/* Header Section */}
                <div className="text-center mb-16 relative">
                    <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-64 h-64 rounded-full bg-safe/10 blur-3xl pointer-events-none" />

                    <div className="relative z-10 flex items-center justify-center gap-2 px-3 py-1.5 rounded-full border border-safe/20 bg-safe/5 text-safe text-xs font-mono mb-6 mx-auto w-max">
                        <span className="w-1.5 h-1.5 rounded-full bg-safe animate-pulse-slow" />
                        Latest Release: {VERSION}
                    </div>

                    <h1 className="relative z-10 text-4xl sm:text-5xl font-bold text-slate-100 mb-4 tracking-tight" style={{ fontFamily: 'Syne, sans-serif' }}>
                        Download <span className="text-gradient-attack">K8sAttackMap</span>
                    </h1>
                    <p className="relative z-10 text-slate-400 text-sm sm:text-base max-w-2xl mx-auto leading-relaxed">
                        Get the GraalVM native binaries for your operating system. No JVM or dependencies required. Cold starts in milliseconds.
                    </p>
                </div>

                {/* Download Grid */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-20 relative z-10">
                    {platforms.map((plat) => (
                        <div key={plat.id} className={`feature-card border ${plat.borderColor} bg-surface-800 transition-all duration-300 ${plat.shadowColor} hover:shadow-xl rounded-xl p-6 flex flex-col`}>
                            <div className="flex items-center gap-3 mb-4">
                                <div className="w-12 h-12 rounded-lg bg-surface-900 border border-slate-700 flex items-center justify-center">
                                    {plat.icon}
                                </div>
                                <h2 className="text-xl font-semibold text-slate-100" style={{ fontFamily: 'Syne, sans-serif' }}>{plat.title}</h2>
                            </div>
                            <p className="text-slate-400 text-sm mb-6 flex-1">{plat.description}</p>

                            <div className="flex flex-col gap-3">
                                {plat.artifacts.map((artifact) => (
                                    <a
                                        key={artifact.label}
                                        href={`${REPO_BASE}/${VERSION}/${artifact.file}`}
                                        className="group flex items-center justify-between w-full p-3 rounded-lg bg-surface-700/50 border border-slate-700 hover:border-slate-500 transition-colors text-sm"
                                    >
                                        <span className="text-slate-300 font-medium group-hover:text-white transition-colors">{artifact.label}</span>
                                        <Download size={16} className="text-slate-500 group-hover:text-safe transition-colors" />
                                    </a>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>

                {/* Terminal Instructions Section */}
                <div className="relative z-10 max-w-3xl mx-auto bg-surface-800 border border-slate-700 rounded-xl overflow-hidden shadow-lg">
                    <div className="border-b border-slate-700 bg-surface-900/50 p-4 flex items-center justify-between">
                        <div className="flex items-center gap-2">
                            <Terminal size={18} className="text-slate-400" />
                            <span className="font-semibold text-slate-200 text-sm" style={{ fontFamily: 'Syne, sans-serif' }}>Quick Install (Linux / macOS)</span>
                        </div>
                    </div>
                    <div className="p-6">
                        <div className="terminal text-xs sm:text-sm">
                            <div className="terminal-header">
                                <div className="terminal-dot bg-red-500" />
                                <div className="terminal-dot bg-yellow-500" />
                                <div className="terminal-dot bg-green-500" />
                            </div>
                            <div className="p-5 font-mono leading-relaxed overflow-x-auto whitespace-pre">
                                <span className="text-slate-500"># 1. Download the binary (Example: Linux x86_64)</span>
                                <br/>
                                <span className="text-safe">curl</span>
                                <span className="text-slate-300"> -LO {REPO_BASE}/{VERSION}/K8sAttackMap-{VERSION}-linux-x86_64</span>
                                <br/><br/>
                                <span className="text-slate-500"># 2. Make it executable</span>
                                <br/>
                                <span className="text-safe">chmod</span>
                                <span className="text-slate-300"> +x K8sAttackMap-{VERSION}-linux-x86_64</span>
                                <br/><br/>
                                <span className="text-slate-500"># 3. Run the tool</span>
                                <br/>
                                <span className="text-slate-300">./K8sAttackMap-{VERSION}-linux-x86_64 </span>
                                <span className="text-node">--help</span>
                            </div>
                        </div>

                        <div className="mt-6 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 text-sm">
                            <div className="flex items-center gap-2 text-slate-400">
                                <CheckCircle2 size={16} className="text-node" />
                                <span>Requires Trivy for CVE-aware scoring.</span>
                            </div>
                            <Link href="/docs/getting-started/installation" className="flex items-center gap-1.5 text-safe hover:text-safe/80 transition-colors font-medium">
                                View Full Installation Guide <ArrowRight size={16} />
                            </Link>
                        </div>
                    </div>
                </div>
            </main>

            <Footer />
        </div>
    );
}