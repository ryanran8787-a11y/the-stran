export default function TagChip({ tag, active = false }: { tag: string; active?: boolean }) {
  return (
    <span
      className="inline-flex items-center rounded-full border px-2 py-[1px] text-[11.5px]"
      style={
        active
          ? { background: "var(--fg)", color: "var(--bg)", borderColor: "var(--fg)" }
          : { color: "var(--muted)" }
      }
    >
      {tag}
    </span>
  );
}
