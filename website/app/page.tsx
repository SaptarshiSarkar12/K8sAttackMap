'use client';

import Link from 'next/link';
import {
  AlertTriangle,
  ArrowRight,
  BarChart3,
  ChevronRight,
  Crosshair,
  ExternalLink,
  FileText,
  GitBranch,
  Globe,
  Lock,
  MessageSquare,
  Package,
  RefreshCw,
  Search,
  Shield,
  Terminal,
  Zap,
} from 'lucide-react';
import {FaGithub} from "react-icons/fa";
import {ImageZoom} from "fumadocs-ui/components/image-zoom";

// ─── Hero Section ────────────────────────────────────────────────────────────
function Hero() {
  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden px-4 pt-20 pb-16">
      {/* Animated grid background */}
      <div className="absolute inset-0 bg-grid opacity-100 pointer-events-none" />
      {/* Radial glow spots */}
      <div className="absolute top-1/4 left-1/4 w-96 h-96 rounded-full bg-attack/5 blur-3xl pointer-events-none" />
      <div className="absolute bottom-1/4 right-1/4 w-96 h-96 rounded-full bg-safe/5 blur-3xl pointer-events-none" />

      {/* Version badge */}
      <div className="relative z-10 flex items-center gap-2 px-3 py-1.5 rounded-full border border-safe/20 bg-safe/5 text-safe text-xs font-mono mb-8">
        <span className="w-1.5 h-1.5 rounded-full bg-node animate-pulse-slow" />
        v1.0.0 &nbsp;·&nbsp; Open Source &nbsp;·&nbsp; GraalVM Native
      </div>

      {/* Main heading */}
      <h1
        className="relative z-10 text-center text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight max-w-5xl mx-auto leading-[1.1]"
        style={{ fontFamily: 'Syne, sans-serif' }}
      >
        <span className="block text-slate-100">Map Your Kubernetes</span>
        <span className="block text-gradient-attack mt-1">Attack Surface</span>
      </h1>

      {/* Sub-heading */}
      <p className="relative z-10 mt-6 text-center text-slate-400 text-base sm:text-lg max-w-2xl mx-auto leading-relaxed">
        Ingest a cluster snapshot, build a{' '}
        <span className="text-safe font-medium">directed attack graph</span> across RBAC, workloads,
        secrets, and nodes — then surface the most dangerous paths, choke points, and{' '}
        <span className="text-node font-medium">actionable remediation</span> in a single command.
      </p>

      {/* CTA buttons */}
      <div className="relative z-10 mt-10 flex flex-col sm:flex-row gap-4 justify-center">
        <Link
          href="/docs"
          className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg font-semibold text-sm bg-safe text-surface-900 hover:bg-safe/90 transition-all duration-200 hover:shadow-lg hover:shadow-safe/20"
        >
          Get Started
          <ChevronRight size={16} />
        </Link>
        <a
          href="https://github.com/SaptarshiSarkar12/K8sAttackMap"
          target="_blank"
          rel="noopener noreferrer"
          className="inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg font-semibold text-sm border border-slate-700 text-slate-300 hover:border-safe/40 hover:text-safe transition-all duration-200"
        >
          <FaGithub size={16} />
          View on GitHub
        </a>
      </div>

      {/* Mini terminal preview */}
      <div className="relative z-10 mt-14 w-full max-w-2xl mx-auto terminal text-sm">
        <div className="terminal-header">
          <div className="terminal-dot bg-red-500" />
          <div className="terminal-dot bg-yellow-500" />
          <div className="terminal-dot bg-green-500" />
          <span className="ml-3 text-slate-500 text-xs font-mono">bash</span>
        </div>
        <div className="p-5 font-mono text-xs sm:text-sm leading-relaxed overflow-x-auto">
          <div className="flex flex-wrap gap-x-1">
            <span className="text-node">$</span>
            <span className="text-slate-300">{'./k8sattackmap'}</span>
            <span className="text-safe">{' -k cluster-state.json'}</span>
            <span className="text-slate-400">{' -o html,pdf'}</span>
          </div>
          <div className="mt-3 text-slate-500">
            <span className="text-safe/70">{'[INFO] '}</span>Parsing 248 resources…
          </div>
          <div className="text-slate-500">
            <span className="text-safe/70">{'[INFO] '}</span>Running Trivy CVE scan on 12 images…
          </div>
          <div className="mt-1 text-slate-500">
            <span className="text-attack/70">{'[WARN] '}</span>
            Attack path found: <span className="text-attack">Pod:default:api-server</span>
            <span className="text-slate-600"> → </span>
            <span className="text-yellow-400">ServiceAccount:default:ci-runner</span>
            <span className="text-slate-600"> → </span>
            <span className="text-attack">Secret:prod:stripe-key</span>
          </div>
          <div className="mt-1 text-slate-500">
            <span className="text-node/70">{'[INFO] '}</span>Choke point: <span className="text-node">ServiceAccount:default:ci-runner</span>{' '}
            <span className="text-slate-600">(severs 7 paths)</span>
          </div>
          <div className="mt-2 text-slate-500">
            <span className="text-slate-400">{'→ '}</span>
            <span className="text-slate-300">k8s-threat-map.html</span>
            <span className="text-slate-500"> written</span>
          </div>
          <div className="text-slate-500">
            <span className="text-slate-400">{'→ '}</span>
            <span className="text-slate-300">k8s-threat-report.pdf</span>
            <span className="text-slate-500"> written</span>
          </div>
          <div className="mt-3 flex items-center gap-1">
            <span className="text-node">$</span>
            <span className="w-2 h-4 bg-slate-400 animate-pulse ml-1" />
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Why K8sAttackMap ─────────────────────────────────────────────────────────
function Why() {
  return (
    <section className="relative py-24 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <h2
            className="text-3xl sm:text-4xl font-bold text-slate-100 mb-4"
            style={{ fontFamily: 'Syne, sans-serif' }}
          >
            Why <span className="text-gradient-attack">K8sAttackMap?</span>
          </h2>
          <p className="text-slate-400 max-w-2xl mx-auto text-base leading-relaxed">
            Most Kubernetes security tools check policy compliance in isolation — they tell you a pod is
            privileged or a role has wildcard verbs, but they don&apos;t tell you{' '}
            <em>what an attacker can actually reach</em> from that misconfiguration.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {[
            {
              icon: <Search size={22} className="text-attack" />,
              title: 'Connects the Dots',
              body: 'Parses every workload, RBAC binding, secret, and service account relationship across all namespaces to build a complete attack surface model.',
            },
            {
              icon: <BarChart3 size={22} className="text-safe" />,
              title: 'CVE-Aware Scoring',
              body: 'Integrates Trivy vulnerability scan results directly into edge weights. A pod running a critical-CVE image gets a lower-friction traversal score.',
            },
            {
              icon: <Zap size={22} className="text-node" />,
              title: 'Actionable Output',
              body: 'Every choke point and attack path comes with prioritised kubectl remediation commands — suitable for both daily ops and formal security audits.',
            },
          ].map((item) => (
            <div key={item.title} className="feature-card">
              <div className="w-10 h-10 rounded-lg flex items-center justify-center mb-4 bg-surface-800 border border-slate-700">
                {item.icon}
              </div>
              <h3
                className="text-lg font-semibold text-slate-100 mb-2"
                style={{ fontFamily: 'Syne, sans-serif' }}
              >
                {item.title}
              </h3>
              <p className="text-slate-400 text-sm leading-relaxed">{item.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── How It Works (Pipeline) ──────────────────────────────────────────────────
function Pipeline() {
  const stages = [
    {
      icon: <Package size={20} />,
      color: 'text-node',
      bg: 'bg-node/10 border-node/20',
      label: '1. Ingest',
      detail: 'kubectl live capture or JSON snapshot',
    },
    {
      icon: <Search size={20} />,
      color: 'text-safe',
      bg: 'bg-safe/10 border-safe/20',
      label: '2. Parse & Scan',
      detail: 'K8sJsonParser + Trivy CVE scan',
    },
    {
      icon: <GitBranch size={20} />,
      color: 'text-blue-400',
      bg: 'bg-blue-400/10 border-blue-400/20',
      label: '3. Build Graph',
      detail: 'Directed weighted multigraph',
    },
    {
      icon: <Crosshair size={20} />,
      color: 'text-purple-400',
      bg: 'bg-purple-400/10 border-purple-400/20',
      label: '4. Analyse',
      detail: 'Dijkstra · BFS · Johnson\'s cycles',
    },
    {
      icon: <FileText size={20} />,
      color: 'text-attack',
      bg: 'bg-attack/10 border-attack/20',
      label: '5. Report',
      detail: 'Console · HTML map · PDF audit',
    },
  ];

  return (
    <section className="relative py-24 px-4 bg-surface-800/40">
      <div className="absolute inset-0 bg-grid opacity-50 pointer-events-none" />
      <div className="relative max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <h2
            className="text-3xl sm:text-4xl font-bold text-slate-100 mb-4"
            style={{ fontFamily: 'Syne, sans-serif' }}
          >
            How It <span className="text-gradient-safe">Works</span>
          </h2>
          <p className="text-slate-400 max-w-xl mx-auto text-sm">
            Five stages from raw cluster data to prioritised attack intelligence.
          </p>
        </div>

        {/* Desktop pipeline row */}
        <div className="hidden lg:flex items-center justify-center gap-0">
          {stages.map((stage, i) => (
            <div key={stage.label} className="flex items-center">
              <div className="pipeline-node w-40">
                <div className={`pipeline-icon border ${stage.bg} ${stage.color} w-14 h-14`}>
                  {stage.icon}
                </div>
                <p
                  className={`text-sm font-semibold ${stage.color} mb-1`}
                  style={{ fontFamily: 'Syne, sans-serif' }}
                >
                  {stage.label}
                </p>
                <p className="text-xs text-slate-500 leading-tight">{stage.detail}</p>
              </div>
              {i < stages.length - 1 && (
                <div className="flex items-center mx-1">
                  <div className="w-8 h-px bg-linear-to-r from-slate-700 to-slate-600" />
                  <ArrowRight size={12} className="text-slate-600 -ml-1" />
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Mobile pipeline stack */}
        <div className="flex lg:hidden flex-col gap-4 max-w-sm mx-auto">
          {stages.map((stage, i) => (
            <div key={stage.label} className="flex items-start gap-4">
              <div className={`shrink-0 w-10 h-10 rounded-lg flex items-center justify-center border ${stage.bg} ${stage.color}`}>
                {stage.icon}
              </div>
              <div className="pt-1">
                <p className={`text-sm font-semibold ${stage.color}`} style={{ fontFamily: 'Syne, sans-serif' }}>
                  {stage.label}
                </p>
                <p className="text-xs text-slate-500 mt-0.5">{stage.detail}</p>
              </div>
              {i < stages.length - 1 && (
                <div className="absolute left-9 w-px h-4 bg-slate-700 translate-y-10" />
              )}
            </div>
          ))}
        </div>

        {/* Edge weight callout */}
        <div className="mt-14 max-w-2xl mx-auto terminal text-xs">
          <div className="terminal-header">
            <div className="terminal-dot bg-red-500" />
            <div className="terminal-dot bg-yellow-500" />
            <div className="terminal-dot bg-green-500" />
            <span className="ml-2 text-slate-500 font-mono">Edge weight formula</span>
          </div>
          <div className="p-5 font-mono leading-relaxed">
            <span className="text-slate-500">// Lower friction = easier attacker movement</span>
            <br />
            <span className="text-safe">friction</span>
            <span className="text-slate-400"> = </span>
            <span className="text-slate-300">{'(0.45 × source.intrinsic) + (0.55 × target.intrinsic)'}</span>
            <br />
            <span className="text-safe">friction</span>
            <span className="text-slate-400"> -= </span>
            <span className="text-attack">cveBonus</span>
            <span className="text-slate-500"> // critical CVE → lower friction</span>
            <br />
            <span className="text-safe">friction</span>
            <span className="text-slate-400"> -= </span>
            <span className="text-attack">privilegedPenalty</span>
            <span className="text-slate-500"> // privileged container → easier traversal</span>
            <br />
            <span className="text-safe">friction</span>
            <span className="text-slate-400"> = </span>
            <span className="text-slate-300">clamp(friction, 0.1, 25.0)</span>
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Key Features ─────────────────────────────────────────────────────────────
function Features() {
  const features = [
    {
      icon: <GitBranch size={20} className="text-attack" />,
      title: 'Attack Path Discovery',
      desc: 'Dijkstra finds the shortest (most dangerous) path. AllDirectedPaths surfaces all simple routes up to configurable depth, grouped by source→target pair.',
    },
    {
      icon: <Crosshair size={20} className="text-safe" />,
      title: 'Choke Point Ranking',
      desc: "Nodes ranked by the number of attack paths severed if hardened. The top-5 choke points — with weighted impact scores — tell you exactly where to focus.",
    },
    {
      icon: <RefreshCw size={20} className="text-node" />,
      title: 'Privilege Escalation Loops',
      desc: "Johnson's simple-cycle algorithm detects circular RBAC chains. An RBAC-only filter removes infrastructure ownership false positives.",
    },
    {
      icon: <Globe size={20} className="text-purple-400" />,
      title: 'Blast Radius Analysis',
      desc: 'BFS from each compromised entry point up to configurable hop depth. Every impacted asset is labelled with its severity — Critical, High, Medium, or Low.',
    },
    {
      icon: <AlertTriangle size={20} className="text-yellow-400" />,
      title: 'CVE-Aware Edge Weights',
      desc: 'Trivy scan results feed directly into edge friction. A pod running a critical-CVE image gets a lower-friction traversal, reflecting real attacker economics.',
    },
    {
      icon: <Lock size={20} className="text-attack" />,
      title: 'Complete Edge Vocabulary',
      desc: 'USES_SA · BOUND_TO · CAN_ACCESS · NODE_ESCAPE · EXEC_INTO · MINTS_TOKEN · HOST_PATH_ACCESS — 19 semantic edge types model every real attack capability.',
    },
    {
      icon: <Terminal size={20} className="text-safe" />,
      title: 'GraalVM Native Binary',
      desc: 'Built with GraalVM Native Image. No JVM required at runtime. Cold starts in milliseconds. Linux, macOS, and Windows binaries on every release.',
    },
    {
      icon: <FileText size={20} className="text-node" />,
      title: 'HTML + PDF Exports',
      desc: 'Interactive Cytoscape.js graph with blast-radius highlighting. Structured PDF audit report with executive summary, remediation cards, and CVE tables.',
    },
    {
      icon: <Shield size={20} className="text-purple-400" />,
      title: 'Actionable Remediation',
      desc: 'Every choke point comes with specific kubectl audit and enforcement commands — from removing ClusterRoleBindings to enforcing Pod Security Standards.',
    },
  ];

  return (
    <section className="relative py-24 px-4">
      <div className="max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <h2
            className="text-3xl sm:text-4xl font-bold text-slate-100 mb-4"
            style={{ fontFamily: 'Syne, sans-serif' }}
          >
            Key <span className="text-gradient-safe">Features</span>
          </h2>
          <p className="text-slate-400 max-w-xl mx-auto text-sm">
            A complete security intelligence pipeline — from raw cluster data to prioritised, executable remediation.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {features.map((f) => (
            <div key={f.title} className="feature-card group">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-md bg-surface-700 flex items-center justify-center border border-slate-700 group-hover:border-safe/30 transition-colors">
                  {f.icon}
                </div>
                <h3
                  className="text-sm font-semibold text-slate-200"
                  style={{ fontFamily: 'Syne, sans-serif' }}
                >
                  {f.title}
                </h3>
              </div>
              <p className="text-slate-500 text-xs leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ─── Output Formats ───────────────────────────────────────────────────────────
function Outputs() {
  return (
    <section className="relative py-24 px-4 bg-surface-800/40">
      <div className="absolute inset-0 bg-grid opacity-50 pointer-events-none" />
      <div className="relative max-w-6xl mx-auto">
        <div className="text-center mb-16">
          <h2
            className="text-3xl sm:text-4xl font-bold text-slate-100 mb-4"
            style={{ fontFamily: 'Syne, sans-serif' }}
          >
            Output <span className="text-gradient-attack">Formats</span>
          </h2>
          <p className="text-slate-400 max-w-xl mx-auto text-sm">
            Three output channels, each optimised for a different audience and use case.
          </p>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Console */}
          <div className="feature-card flex flex-col">
            <div className="flex items-center gap-2 mb-4">
              <Terminal size={18} className="text-node" />
              <span className="font-semibold text-slate-200 text-sm" style={{ fontFamily: 'Syne, sans-serif' }}>
                Console Output
              </span>
              <span className="ml-auto text-xs text-slate-600 font-mono">always on</span>
            </div>
            <p className="text-slate-500 text-xs leading-relaxed mb-4">
              Color-coded terminal output with attack paths, choke point rankings, blast radius summary, privilege escalation loops, and per-path remediation steps.
            </p>
            <div className="mt-auto rounded-md border border-slate-700 bg-surface-800 h-50 flex items-center justify-center text-slate-600 text-xs font-mono">
              <ImageZoom src={"/terminal_screenshot.png"} alt={"Terminal Screenshot"} width={2560} height={1600} className={"rounded-md"} />
            </div>
          </div>

          {/* HTML */}
          <div className="feature-card flex flex-col border-safe/20">
            <div className="flex items-center gap-2 mb-4">
              <Globe size={18} className="text-safe" />
              <span className="font-semibold text-slate-200 text-sm" style={{ fontFamily: 'Syne, sans-serif' }}>
                HTML Visualisation
              </span>
              <span className="ml-auto text-xs text-slate-600 font-mono">-o html</span>
            </div>
            <p className="text-slate-500 text-xs leading-relaxed mb-4">
              Interactive Cytoscape.js graph. Entry points in green hexagons, choke points in grey, blast radius in yellow, attack paths in red. Edges labelled by type and risk weight.
            </p>
            <div className="mt-auto rounded-md border border-slate-700 bg-surface-800 h-50 flex items-center justify-center text-slate-600 text-xs font-mono">
              <ImageZoom src={"/html_visualisation_screenshot.png"} alt={"Screenshot of HTML visualisation of kubernetes cluster"} width={2560} height={1600} className={"rounded-md"} />
            </div>
          </div>

          {/* PDF */}
          <div className="feature-card flex flex-col">
            <div className="flex items-center gap-2 mb-4">
              <FileText size={18} className="text-attack" />
              <span className="font-semibold text-slate-200 text-sm" style={{ fontFamily: 'Syne, sans-serif' }}>
                PDF Threat Report
              </span>
              <span className="ml-auto text-xs text-slate-600 font-mono">-o pdf</span>
            </div>
            <p className="text-slate-500 text-xs leading-relaxed mb-4">
              Structured audit report with executive summary, risk grade, choke point table, critical attack path hop-by-hop breakdown, remediation cards, and CVE summary.
            </p>
            <div className="mt-auto rounded-md border border-slate-700 bg-surface-800 h-58 flex items-center justify-center text-slate-600 text-xs font-mono">
              <ImageZoom src={"/pdf_report_screenshot_cropped.png"} alt={"PDF report cover screenshot"} width={1585} height={1200} className={"rounded-md"} />
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

// ─── Quick Start ──────────────────────────────────────────────────────────────
function QuickStart() {
  const steps = [
    {
      num: '01',
      title: 'Install Trivy',
      code: `# macOS
brew install aquasecurity/trivy/trivy

# Linux
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin`,
    },
    {
      num: '02',
      title: 'Download K8sAttackMap',
      code: `# Get the latest binary from GitHub Releases
# Then make it executable (Linux / macOS):
chmod +x k8sattackmap
./k8sattackmap --version`,
    },
    {
      num: '03',
      title: 'Run Against Your Cluster',
      code: `# Capture cluster snapshot
kubectl get pods,services,serviceaccounts,roles,clusterroles,\\
  rolebindings,clusterrolebindings,secrets,configmaps,\\
  deployments,replicasets,daemonsets,statefulsets,nodes \\
  -A -o json > cluster-state.json

# Analyse and generate all outputs
./k8sattackmap -k cluster-state.json -o html,pdf`,
    },
  ];

  return (
    <section className="relative py-24 px-4">
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-16">
          <h2
            className="text-3xl sm:text-4xl font-bold text-slate-100 mb-4"
            style={{ fontFamily: 'Syne, sans-serif' }}
          >
            Quick <span className="text-gradient-safe">Start</span>
          </h2>
          <p className="text-slate-400 max-w-xl mx-auto text-sm">
            From zero to your first attack map in under two minutes.
          </p>
        </div>

        <div className="flex flex-col gap-6">
          {steps.map((step) => (
            <div key={step.num} className="flex gap-5 items-start">
              <div className="shrink-0 w-10 h-10 rounded-full border border-safe/30 bg-safe/5 flex items-center justify-center font-mono text-xs font-bold text-safe">
                {step.num}
              </div>
              <div className="flex-1 min-w-0">
                <h3
                  className="text-base font-semibold text-slate-200 mb-3"
                  style={{ fontFamily: 'Syne, sans-serif' }}
                >
                  {step.title}
                </h3>
                <div className="terminal text-xs">
                  <div className="terminal-header">
                    <div className="terminal-dot bg-red-500" />
                    <div className="terminal-dot bg-yellow-500" />
                    <div className="terminal-dot bg-green-500" />
                  </div>
                  <pre className="p-4 text-slate-300 font-mono text-xs leading-relaxed overflow-x-auto whitespace-pre-wrap wrap-break-word">
                    {step.code}
                  </pre>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-12 text-center">
          <Link
            href="/docs/getting-started"
            className="inline-flex items-center gap-2 text-sm text-safe hover:text-safe/80 transition-colors"
          >
            Full installation guide
            <ExternalLink size={14} />
          </Link>
        </div>
      </div>
    </section>
  );
}

// ─── Community ────────────────────────────────────────────────────────────────
function Community() {
  return (
    <section className="relative py-20 px-4 bg-surface-800/40 border-t border-slate-800">
      <div className="absolute inset-0 bg-grid opacity-50 pointer-events-none" />
      <div className="relative max-w-4xl mx-auto text-center">
        <h2
          className="text-2xl sm:text-3xl font-bold text-slate-100 mb-4"
          style={{ fontFamily: 'Syne, sans-serif' }}
        >
          Community &amp; Contributing
        </h2>
        <p className="text-slate-400 text-sm max-w-xl mx-auto mb-10 leading-relaxed">
          K8sAttackMap is open source under the Apache 2.0 license. Bug reports, feature requests, documentation improvements, and test contributions are all welcome.
        </p>

        <div className="flex flex-col sm:flex-row gap-4 justify-center">
          <a
            href="https://github.com/SaptarshiSarkar12/K8sAttackMap"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg border border-slate-700 text-slate-300 text-sm hover:border-safe/40 hover:text-safe transition-all"
          >
            <FaGithub size={15} />
            GitHub Repository
          </a>
          <a
            href="https://discord.gg/DeT4jXPfkG"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg border border-slate-700 text-slate-300 text-sm hover:border-purple-400/40 hover:text-purple-400 transition-all"
          >
            <MessageSquare size={15} />
            Discord (#k8sattackmap)
          </a>
          <Link
            href="/docs/contributing/getting-started"
            className="inline-flex items-center justify-center gap-2 px-5 py-2.5 rounded-lg border border-slate-700 text-slate-300 text-sm hover:border-node/40 hover:text-node transition-all"
          >
            <Shield size={15} />
            Contributing Guide
          </Link>
        </div>
      </div>
    </section>
  );
}

// ─── Navbar ───────────────────────────────────────────────────────────────────
function Navbar() {
  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-slate-800/60 bg-surface-900/90 backdrop-blur-md">
      <div className="max-w-6xl mx-auto px-4 h-14 flex items-center justify-between">
        <Link href="/" className="flex items-center gap-2.5">
          <Shield size={20} className="text-attack" />
          <span
            className="font-bold text-slate-100 text-sm tracking-wide"
            style={{ fontFamily: 'Syne, sans-serif' }}
          >
            K8sAttackMap
          </span>
        </Link>

        <div className="flex items-center gap-1 sm:gap-2">
          <Link
            href="/docs"
            className="text-xs sm:text-sm text-slate-400 hover:text-slate-200 px-2 sm:px-3 py-1.5 rounded-md transition-colors"
          >
            Docs
          </Link>
          <a
            href="/download"
            className="text-xs sm:text-sm text-slate-400 hover:text-slate-200 px-2 sm:px-3 py-1.5 rounded-md transition-colors"
          >
            Download
          </a>
          <a
            href="https://github.com/SaptarshiSarkar12/K8sAttackMap"
            target="_blank"
            rel="noopener noreferrer"
            className="flex items-center gap-1.5 text-xs sm:text-sm text-slate-400 hover:text-slate-200 px-2 sm:px-3 py-1.5 rounded-md border border-slate-700 hover:border-safe/40 transition-all"
          >
            <FaGithub size={14} />
            <span className="hidden sm:inline">GitHub</span>
          </a>
        </div>
      </div>
    </nav>
  );
}

// ─── Footer ───────────────────────────────────────────────────────────────────
function Footer() {
  return (
    <footer className="border-t border-slate-800 py-10 px-4">
      <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-slate-600">
        <div className="flex items-center gap-2">
          <Shield size={14} className="text-attack/60" />
          <span>K8sAttackMap · Apache License 2.0</span>
        </div>
        <div className="flex items-center gap-4">
          <Link href="/docs" className="hover:text-slate-400 transition-colors">
            Documentation
          </Link>
          <a
            href="https://github.com/SaptarshiSarkar12/K8sAttackMap"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-slate-400 transition-colors"
          >
            GitHub
          </a>
          <Link href="/docs/contributing/getting-started" className="hover:text-slate-400 transition-colors">
            Contribute
          </Link>
        </div>
      </div>
    </footer>
  );
}

// ─── Page ─────────────────────────────────────────────────────────────────────
export default function Home() {
  return (
    <div className="min-h-screen bg-surface-900">
      <Navbar />
      <main>
        <Hero />
        <Why />
        <Pipeline />
        <Features />
        <Outputs />
        <QuickStart />
        <Community />
      </main>
      <Footer />
    </div>
  );
}
