/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  // Allow binary body for DoH requests
  experimental: {
    serverComponentsExternalPackages: ['dns-packet'],
  },
};

export default nextConfig;

