import fs from "node:fs/promises";
import path from "node:path";
import { type NextRequest, NextResponse } from "next/server";

const MIME_MAP: Record<string, string> = {
  jpg: "image/jpeg",
  jpeg: "image/jpeg",
  png: "image/png",
  gif: "image/gif",
  webp: "image/webp",
  svg: "image/svg+xml",
  avif: "image/avif",
  ico: "image/x-icon",
  bmp: "image/bmp",
  tiff: "image/tiff",
  tif: "image/tiff",
  heic: "image/heic",
  heif: "image/heif",
};

export async function GET(
  _request: NextRequest,
  context: { params: Promise<{ path: string[] }> },
) {
  try {
    const { path: segments } = await context.params;
    if (!segments || segments.length === 0) {
      return new NextResponse("File path required", { status: 400 });
    }

    // Each segment arrives URL-decoded, so one segment can hold "../.." or
    // "a/b": reject those outright, then check that the resolved path is
    // still inside public/uploads, and serve only known image types.
    if (
      segments.some(
        (s) =>
          !s ||
          s === "." ||
          s === ".." ||
          s.includes("/") ||
          s.includes("\\") ||
          s.includes("\0"),
      )
    ) {
      return new NextResponse("Not Found", { status: 404 });
    }

    const uploadsDir = path.resolve(process.cwd(), "public", "uploads");
    const filePath = path.resolve(uploadsDir, ...segments);
    const ext = path.extname(filePath).replace(/^\./, "").toLowerCase();
    if (!filePath.startsWith(uploadsDir + path.sep) || !MIME_MAP[ext]) {
      return new NextResponse("Not Found", { status: 404 });
    }

    const buffer = await fs.readFile(filePath);
    const contentType = MIME_MAP[ext];

    return new NextResponse(buffer, {
      headers: {
        "Content-Type": contentType,
        "Cache-Control": "public, max-age=31536000, immutable",
        "X-Content-Type-Options": "nosniff",
      },
    });
  } catch {
    return new NextResponse("Not Found", { status: 404 });
  }
}
