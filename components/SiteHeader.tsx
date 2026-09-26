import Link from "next/link";

const NAV = [
  { href: "/", label: "最新一期" },
  { href: "/archive", label: "歷史存檔" },
  { href: "/feed.xml", label: "RSS" },
];

export default function SiteHeader() {
  return (
    <header
      className="sticky top-0 z-20 border-b backdrop-blur-md"
      style={{ background: "color-mix(in srgb, var(--bg) 82%, transparent)" }}
    >
      <div className="aurora" />
      <div className="mx-auto flex h-14 max-w-5xl items-center gap-3 px-4 sm:px-6">
        <Link href="/" className="flex items-center gap-2.5">
          <svg
            aria-hidden="true"
            width="18"
            height="16"
            viewBox="0 0 24 22"
            className="shrink-0"
            style={{ color: "var(--fg)" }}
          >
            <path d="M12 0 24 22H0z" fill="currentColor" />
          </svg>
          <span className="text-[15px] font-semibold tracking-tight">Security Daily</span>
          <span className="hidden text-[12px] sm:inline" style={{ color: "var(--muted)" }}>
            網安每日報
          </span>
        </Link>

        <nav className="ml-auto flex items-center gap-1 text-[13px]">
          {NAV.map((entry) => (
            <Link
              key={entry.href}
              href={entry.href}
              className="rounded-md px-2.5 py-1.5 transition-colors hover:bg-[var(--bg-soft)]"
              style={{ color: "var(--muted)" }}
            >
              {entry.label}
            </Link>
          ))}
          <a
            href="https://github.com/ryanran8787-a11y/the-stran"
            target="_blank"
            rel="noreferrer"
            className="rounded-md px-2.5 py-1.5 transition-colors hover:bg-[var(--bg-soft)]"
            style={{ color: "var(--muted)" }}
          >
            GitHub
          </a>
        </nav>
      </div>
    </header>
  );
}
