import { type NextRequest, NextResponse } from "next/server";
import { isAuthenticated } from "@/lib/auth";

export async function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;

  // Always allow Next.js internals, static assets, and favicon
  if (
    pathname.startsWith("/_next") ||
    pathname === "/favicon.ico" ||
    pathname.startsWith("/uploads/")
  ) {
    return NextResponse.next();
  }

  // If authentication is explicitly disabled
  if (process.env.DISABLE_AUTH === "true") {
    return NextResponse.next();
  }

  // Public endpoints accessible to guests:
  // - /login, /api/login and /api/logout (logout must clear a cookie that
  //   no longer verifies, e.g. after the key changed)
  // - / (public asset gallery)
  // - GET /api/images (public asset catalog)
  if (
    pathname === "/login" ||
    pathname === "/api/login" ||
    pathname === "/api/logout" ||
    pathname === "/" ||
    (pathname === "/api/images" &&
      (request.method === "GET" || request.method === "HEAD"))
  ) {
    return NextResponse.next();
  }

  // Valid bearer token, or a valid session cookie (on a change, sent from
  // this site's own pages)
  if (!(await isAuthenticated(request))) {
    // Return 401 for APIs, redirect to login for protected pages
    if (pathname.startsWith("/api/")) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
    return NextResponse.redirect(new URL("/login", request.url));
  }

  return NextResponse.next();
}

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
