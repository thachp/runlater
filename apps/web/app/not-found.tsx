import Link from "next/link";

export default function NotFound() {
  return (
    <section className="wrap cta">
      <p className="eyebrow">404</p>
      <h1>Nothing here</h1>
      <p>That page doesn't exist.</p>
      <Link className="button primary" href="/">
        Back home
      </Link>
    </section>
  );
}
