import type { NextConfig } from "next";

// Render blueprints hand the API's hostname over without a scheme, so accept both.
const rawApiBase = process.env.API_INTERNAL_URL?.trim() || "http://127.0.0.1:8000";
const apiBase = /^https?:\/\//.test(rawApiBase) ? rawApiBase : `https://${rawApiBase}`;

const nextConfig: NextConfig = {
  distDir: process.env.NEXT_DIST_DIR || ".next",
  output: "standalone",
  reactStrictMode: true,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${apiBase}/api/:path*` }];
  },
};

export default nextConfig;
