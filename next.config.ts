import type { NextConfig } from "next";

/**
 * 刻意「不使用」 output: 'export'。
 * 全站頁面在 build 時以 SSG 預先渲染（generateStaticParams），
 * 但保留 Route Handlers / sitemap / 未來動態 API 與 ISR 的擴充空間。
 */
const nextConfig: NextConfig = {
  reactStrictMode: true,
  poweredByHeader: false,
  // 本站沒有圖片資產，關閉 Image Optimization 可省下 Vercel 用量額度。
  images: { unoptimized: true },
  typescript: { ignoreBuildErrors: false },
};

export default nextConfig;
