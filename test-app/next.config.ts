import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  cacheComponents: true,
  partialPrefetching: true,
  transpilePackages: [
    "@authplatform/auth-core",
    "@authplatform/auth-nextjs",
    "@authplatform/auth-react",
  ],
};

export default nextConfig;
