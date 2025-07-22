import { OAuth2Client } from "https://deno.land/x/oauth2_client@v1.0.2/mod.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.9.1/mod.ts";

// --- 环境变量获取函数 ---
const getEnv = (key: string, defaultValue: string = "") => Deno.env.get(key) || defaultValue;

// --- OAuth2 客户端配置函数 ---
function createOAuth2Client(requestUrl: URL) {
  const deploymentUrl = getEnv("DEPLOYMENT_URL");
  const baseUrl = deploymentUrl ? `https://${deploymentUrl}` : requestUrl.origin;

  return new OAuth2Client({
    clientId: getEnv("LINUX_DO_CLIENT_ID"),
    clientSecret: getEnv("LINUX_DO_CLIENT_SECRET"),
    authorizationEndpointUri: "https://connect.linux.do/oauth2/authorize",
    tokenUri: "https://connect.linux.do/oauth2/token",
    redirectUri: `${baseUrl}/auth/callback`,
    defaults: {
      scope: "read",
    },
  });
}

// --- 核心请求处理器 ---
async function handler(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const pathname = url.pathname;

  // 预检请求处理 (CORS)
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

  // 路由1: /login
  if (pathname === "/login") {
    const oauth2Client = createOAuth2Client(url);
    const authUrl = oauth2Client.code.getAuthorizationUri();
    return new Response(null, {
      status: 302, // 302表示重定向
      headers: { "Location": authUrl.toString() },
    });
  }

  // 路由2: /auth/callback
  if (pathname === "/auth/callback") {
    const oauth2Client = createOAuth2Client(url);
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
      const jwt = await create({ alg: "HS256", typ: "JWT" }, payload, getEnv("JWT_SECRET", "default-secret-key"));
      
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

  // 路由3: /me
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
      const payload = await verify(jwt, getEnv("JWT_SECRET", "default-secret-key"));
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

  // 根路径或其他路径的默认响应
  return new Response("方舟引擎核心 (v4) 正在运行。", {
    headers: { "Access-Control-Allow-Origin": "*" }
  });
}

// --- 启动方舟引擎 (原生模式) ---
console.log("方舟引擎核心已准备就绪 (v4)，使用原生Deno.serve...");
Deno.serve(handler);
