export function Code({ children, label }: { children: string; label?: string }) {
  return (
    <pre className="code" tabIndex={0}>
      {label ? <span className="code-label">{label}</span> : null}
      <code>{children}</code>
    </pre>
  );
}
