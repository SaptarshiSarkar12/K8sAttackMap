# K8sAttackMap Website

This is the official website and documentation for [K8sAttackMap](https://github.com/SaptarshiSarkar12/K8sAttackMap),
built with [Next.js 15](https://nextjs.org/) and [Fumadocs](https://fumadocs.vercel.app/).

## Tech Stack

- **Framework**: Next.js 15 (App Router)
- **Docs engine**: Fumadocs UI + Fumadocs MDX
- **Styling**: Tailwind CSS v3
- **Language**: TypeScript

## Getting Started

### Prerequisites

- Node.js 20+
- npm / pnpm / yarn

### Install and Run

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) in your browser.

### Build for Production

```bash
npm run build
npm run start
```

## Project Structure

```
├── app/
│   ├── layout.tsx          # Root layout (RootProvider, fonts)
│   ├── page.tsx            # Landing page
│   ├── globals.css         # Global CSS + Tailwind
│   └── docs/
│       ├── layout.tsx      # Fumadocs DocsLayout
│       └── [[...slug]]/
│           └── page.tsx    # Dynamic docs page
├── content/
│   └── docs/               # All MDX documentation files
│       ├── index.mdx
│       ├── getting-started/
│       ├── usage/
│       ├── features/
│       ├── output-formats/
│       ├── architecture/
│       └── contributing/
├── lib/
│   └── source.ts           # Fumadocs source loader
├── next.config.mjs         # Next.js + fumadocs-mdx config
├── source.config.ts        # Fumadocs MDX source config
└── tailwind.config.ts      # Tailwind + Fumadocs preset
```

## Adding Documentation

Add new MDX files under `content/docs/`. Each file needs frontmatter:

```mdx
---
title: My New Page
description: A brief description for SEO and the page subtitle.
---

Content goes here...
```

Update the relevant `meta.json` in the same directory to control sidebar ordering:

```json
{
  "title": "Section Title",
  "pages": ["page-one", "page-two", "my-new-page"]
}
```

## Adding Images

Look for `{/* ─── IMAGE PLACEHOLDER */}` comments throughout the MDX files.
Replace the placeholder `<div>` with a Next.js `<Image>` component:

```tsx
import Image from 'next/image';

<Image
  src="/images/my-screenshot.png"
  alt="Descriptive alt text"
  width={1200}
  height={600}
  className="rounded-lg border border-slate-700"
/>
```

Place images in `public/images/` and reference them as `/images/my-screenshot.png`.

For GitHub-hosted images (already used in the README), you can reference them directly:

```tsx
<Image
  src="https://github.com/user-attachments/assets/..."
  alt="Console output"
  width={1200}
  height={600}
  unoptimized  // required for external images without next.config allowedDomains
/>
```

Or add the GitHub CDN domain to `next.config.mjs`:

```js
const config = {
  images: {
    remotePatterns: [
      { protocol: 'https', hostname: 'github.com' },
      { protocol: 'https', hostname: '*.githubusercontent.com' },
    ],
  },
};
```

## Customising the Theme

The colour palette and fonts are defined in:
- `tailwind.config.ts` — custom colours (`attack`, `safe`, `node`, `surface`)
- `app/globals.css` — CSS variables and Fumadocs overrides
- `app/layout.tsx` — Google Fonts imports (Syne + JetBrains Mono)

## Deployment

This site is a standard Next.js app and can be deployed to:
- **Vercel** (recommended) — zero-config, push to deploy
- **Netlify** — works with `next build && next export` for static
- **Self-hosted** — `npm run build && npm run start`

## License

Apache License 2.0 — same as the K8sAttackMap tool itself.
