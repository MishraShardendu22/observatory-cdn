import { type NextRequest, NextResponse } from "next/server";
import {
  clearLoginFailures,
  clientAddress,
  createSessionToken,
  loginBlocked,
  recordLoginFailure,
  SESSION_COOKIE,
  SESSION_MAX_AGE_S,
  safeEqual,
} from "@/lib/auth";

export async function POST(request: NextRequest) {
  const address = clientAddress(request);
  if (loginBlocked(address)) {
    return NextResponse.json(
      { error: "Too many failed attempts. Try again in 15 minutes." },
      { status: 429 },
    );
  }
  try {
    const { username, password } = await request.json();

    const validUsername = process.env.AUTH_USERNAME;
    const validPassword = process.env.AUTH_PASSWORD;

    if (!validUsername || !validPassword) {
      return NextResponse.json(
        {
          error:
            "Server authentication is not configured in environment variables",
        },
        { status: 500 },
      );
    }

    const [userOk, passOk] = await Promise.all([
      safeEqual(String(username ?? ""), validUsername),
      safeEqual(String(password ?? ""), validPassword),
    ]);
    if (userOk && passOk) {
      clearLoginFailures(address);
      const token = await createSessionToken(validUsername);

      const response = NextResponse.json({ success: true });

      response.cookies.set(SESSION_COOKIE, token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
        path: "/",
        maxAge: SESSION_MAX_AGE_S,
      });

      return response;
    }

    recordLoginFailure(address);
    return NextResponse.json({ error: "Invalid credentials" }, { status: 401 });
  } catch (error) {
    console.error("Login error:", error);
    return NextResponse.json({ error: "Login failed" }, { status: 500 });
  }
}
