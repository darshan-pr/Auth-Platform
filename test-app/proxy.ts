import { createMiddleware } from "@authplatform/auth-nextjs/middleware";

export default createMiddleware({ signInUrl: "/sign-in" });

export const config = {
  matcher: ["/protected/:path*"]
};
