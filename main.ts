import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { OAuth2Client } from "https://deno.land/x/oauth2_client@v1.0.2/mod.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.9.1/mod.ts";

// --- 环境变量：这些是我们的机密密钥，需要配置在Deno Deploy中 ---
const LINUX_DO_CLIENT_ID = Deno.env.get("LINUX_DO_CLIENT_ID") || "";
const LINUX_DO_CLIENT_SECRET = Deno.env.get("LINUX_DO_CLIENT_SECRET") || "";
const JWT_SECRET = Deno.env.get("JWT_SECRET") || "default-secret-key"; 
const FRONTEND_URL = Deno.env.get("FRONTEND_URL") || "https://this-is-a-test-galaxy--disstella.on.websim.com/"; // ✅ 已为你更新为你的静态网站地址

// --- OAuth2 客户端配置：告诉Deno如何与Linux.do星门对话 ---
const oauth2Client = new OAuth2Client({
  clientId: LINUX_DO_CLIENT_ID,
  clientSecret: LINUX_DO_CLIENT_SECRET,
  authorizationEndpointUri: "https://connect.linux.do/oauth2/authorize",
  tokenUri: "https://connect.linux.do/oauth2/token",
  redirectUri: "https://your-ark-name.deno.dev/auth/callback", // ⚠️【重要】我们稍后会获得这个地址并回来修改
  defaults: {
    scope: "read",
  },
});

// --- 创建方舟的路由系统 ---
const router = new Router();

// 路由1: /login - 引导用户去Linux.do星门
router.get("/login", (ctx) => {
  const authUrl = oauth2Client.code.getAuthorizationUri();
  ctx.response.redirect(authUrl);
});

// 路由2: /auth/callback - 接收Linux.do星门返回的信号
router.get("/auth/callback", async (ctx) => {
  try {
    const tokens = await oauth2Client.code.getToken(ctx.request.url);
    
    const userResponse = await fetch("https://connect.linux.do/api/user.json", {
      headers: {
        Authorization: `Bearer ${tokens.accessToken}`,
      },
    });
    const userData = await userResponse.json();

    const payload = {
      username: userData.user.username,
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24), // 凭证有效期24小时
    };
    const jwt = await create({ alg: "HS256", typ: "JWT" }, payload, JWT_SECRET);

    ctx.response.redirect(`${FRONTEND_URL}?token=${jwt}`);

  } catch (error) {
    console.error("认证错误:", error);
    ctx.response.body = "认证失败，请重试。";
    ctx.response.status = 500;
  }
});

// 路由3: /me - 前端用凭证来这里换取用户信息
router.get("/me", async (ctx) => {
    const authHeader = ctx.request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        ctx.response.status = 401;
        ctx.response.body = { error: "未授权" };
        return;
    }
    const jwt = authHeader.split(" ")[1];
    try {
        const payload = await verify(jwt, JWT_SECRET);
        ctx.response.body = { username: payload.username };
    } catch (_error) {
        ctx.response.status = 401;
        ctx.response.body = { error: "无效的凭证" };
    }
});


// --- 启动方舟引擎 ---
const app = new Application();

// 启用CORS，允许前端停泊港访问
app.use(async (ctx, next) => {
  ctx.response.headers.set("Access-Control-Allow-Origin", "*");
  await next();
});

app.use(router.routes());
app.use(router.allowedMethods());

console.log("方舟引擎核心已启动，正在监听8000端口...");
await app.listen({ port: 8000 });
