// 文件名: main.ts (最终修正版 v8)
import { OAuth2Client } from "https://deno.land/x/oauth2_client@v1.0.2/mod.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.9.1/mod.ts";

const getEnv = (key: string, defaultValue: string = "") => Deno.env.get(key) || defaultValue;

const REDIRECT_URI = `https://${getEnv("DENO_DEPLOYMENT_URL")}/auth/callback`;

const oauth2Client = new OAuth2Client({
  clientId: getEnv("LINUX_DO_CLIENT_ID"),
  clientSecret: getEnv("LINUX_DO_CLIENT_SECRET"),
  authorizationEndpointUri: "https://connect.linux.do/oauth2/authorize",
  tokenUri: "https://connect.linux.do/oauth2/token",
  redirectUri: REDIRECT_URI,
  defaults: {
    scope: "read",
  },
});

async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const pathname = url.pathname;

  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, OPTIONS",
        "Access-Control-Allow-Headers": "Authorization, Content-Type",
      },
    });
  }

  if (pathname === "/login") {
    const authUrl = oauth2Client.code.getAuthorizationUri();
    return new Response(null, {
      status: 302,
      headers: { "Location": authUrl.toString() },
    });
  }

  if (pathname === "/auth/callback") {
    try {
      const tokens = await oauth2Client.code.getToken(url);
      const userResponse = await fetch("https://connect.linux.do/api/user.json", {
        headers: { Authorization: `Bearer ${tokens.accessToken}` },
      });
      const userData = await userResponse.json();

      const payload = {
        username: userData.user.username,
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
      };
      const jwt = await create({ alg: "HS256", typ: "JWT" }, payload, getEnv("JWT_SECRET", "1593570rt"));
      
      const frontendUrl = getEnv("FRONTEND_URL", "https://this-is-a-test-galaxy--disstella.on.websim.com/");
      return new Response(null, {
        status: 302,
        headers: { "Location": `${frontendUrl}?token=${jwt}` },
      });

    } catch (error) {
      console.error("认证错误:", error);
      return new Response("认证失败，请重试。", { 
        status: 500,
        headers: { "Access-Control-Allow-Origin": "*" } 
      });
    }
  }

  if (pathname === "/me") {
    const authHeader = req.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "未授权" }), { 
        status: 401, 
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } 
      });
    }
    const jwt = authHeader.split(" ")[1];
    try {
        const payload = await verify(jwt, getEnv("JWT_SECRET", "1593570rt"));
        return new Response(JSON.stringify({ username: payload.username }), { 
            status: 200,
            headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
        });
    } catch (_error) {
      return new Response(JSON.stringify({ error: "无效的凭证" }), { 
        status: 401, 
        headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" }
      });
    }
  }

  return new Response("方舟引擎核心 (v8) 正在运行。", {
    headers: { "Access-Control-Allow-Origin": "*" }
  });
}

console.log("方舟引擎核心已准备就绪 (v8)，使用原生Deno.serve...");
Deno.serve(handler);
