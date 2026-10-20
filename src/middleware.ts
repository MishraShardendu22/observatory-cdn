import { type NextRequest, NextResponse } from "next/server";

export function middleware(request: NextRequest) {
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
  // - /login and /api/login
  // - / (public asset gallery)
  // - GET /api/images (public asset catalog)
  if (
    pathname === "/login" ||
    pathname === "/api/login" ||
    pathname === "/" ||
    (pathname === "/api/images" && request.method === "GET")
  ) {
    return NextResponse.next();
  }

  const token = request.cookies.get("auth_token")?.value;

  if (!token) {
    // Return 401 for mutation APIs, redirect to login for protected pages
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
