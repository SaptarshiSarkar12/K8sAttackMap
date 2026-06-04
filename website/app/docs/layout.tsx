import { DocsLayout } from 'fumadocs-ui/layouts/docs';
import type { ReactNode } from 'react';
import { source } from '@/lib/source';
import { Shield } from 'lucide-react';

export default function Layout({ children }: { children: ReactNode }) {
  return (
    <DocsLayout
      tree={source.getPageTree()}
      nav={{
          title: (
              <div className="flex items-center gap-2">
                  <Shield size={16} className="text-red-500" />
                  <span style={{ fontFamily: 'Syne, sans-serif' }} className="font-bold text-sm">
                      K8sAttackMap
                  </span>
              </div>
          ),
          transparentMode: 'none',
      }}
      links={[
        {
          text: 'GitHub',
          url: 'https://github.com/SaptarshiSarkar12/K8sAttackMap',
          external: true,
        },
        {
          text: 'Download',
          url: '/download',
          external: true,
        },
      ]}
      sidebar={{
        collapsible: true,
      }}
      githubUrl={"https://github.com/SaptarshiSarkar12/K8sAttackMap/"}
    >
      {children}
    </DocsLayout>
  );
}
