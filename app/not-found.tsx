import Link from "next/link";

export default function NotFound() {
  return (
    <section className="py-20 text-center">
      <p className="mono text-[12px] uppercase tracking-widest" style={{ color: "var(--muted-2)" }}>
        404
      </p>
      <h1 className="mt-2 text-2xl font-semibold tracking-tight">找不到這個頁面</h1>
      <p className="mt-3 text-[14px]" style={{ color: "var(--muted)" }}>
        你可能輸入了不存在的日期或 CVE 編號。本站只收錄通過高危門檻的項目。
      </p>
      <div className="mt-6 flex justify-center gap-2">
        <Link className="btn" href="/">
          最新一期
        </Link>
        <Link className="btn" href="/archive">
          歷史存檔
        </Link>
      </div>
    </section>
  );
}
