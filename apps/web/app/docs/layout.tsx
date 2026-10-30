import type { ReactNode } from "react";
import { DocsNav } from "../../components/DocsNav";

export default function DocsLayout({ children }: { children: ReactNode }) {
  return (
    <div className="wrap docs">
      <DocsNav />
      <article className="prose">{children}</article>
    </div>
  );
}
