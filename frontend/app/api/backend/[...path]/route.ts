import { NextRequest, NextResponse } from "next/server";
import { API_BASE_URL } from "@/lib/api";

type RouteContext = {
  params: {
    path: string[];
  };
};

async function proxyRequest(request: NextRequest, context: RouteContext) {
  const upstreamUrl = new URL(
    `${API_BASE_URL.replace(/\/$/, "")}/${context.params.path.join("/")}`
  );

  request.nextUrl.searchParams.forEach((value, key) => {
    upstreamUrl.searchParams.set(key, value);
  });

  try {
    const upstreamResponse = await fetch(upstreamUrl, {
      method: request.method,
      cache: "no-store"
    });

    const body = await upstreamResponse.text();

    return new NextResponse(body, {
      status: upstreamResponse.status,
      statusText: upstreamResponse.statusText,
      headers: {
        "content-type":
          upstreamResponse.headers.get("content-type") || "application/json"
      }
    });
  } catch {
    return NextResponse.json(
      {
        detail:
          "FastAPI backend not available. Run: uvicorn backend.app.main:app --reload --port 8001"
      },
      { status: 502 }
    );
  }
}

export const GET = proxyRequest;
