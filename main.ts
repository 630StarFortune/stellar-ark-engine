import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { OAuth2Client } from "https://deno.land/x/oauth2_client@v1.0.2/mod.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.9.1/mod.ts";

// --- 环境变量获取函数 ---
const getEnv = (key: string, defaultValue: string = "") => Deno.env.get(key) || defaultValue;

// --- OAuth2 客户端配置函数 ---
function createOAuth2Client(requestUrl: URL) {
  // Deno Deploy 会提供 DEPLOYMENT_URL 环境变量
  const deploymentUrl = getEnv("DEPLOYMENT_URL");
  // 如果 DEPLOYMENT_URL 存在，就用它，否则从当前请求的 URL 推断
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

// --- 创建方舟的路由系统  ---
const router = new Router();

router.get("/login", (ctx) => {
  const oauth2Client = createOAuth2Client(ctx.request.url);
  const authUrl = oauth2Client.code.getAuthorizationUri();
  ctx.response.redirect(authUrl);
});

router.get("/auth/callback", async (ctx) => {
  const oauth2Client = createOAuth2Client(ctx.request.url);
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
      exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24),
    };
    const jwt = await create({ alg: "HS256", typ: "JWT" }, payload, getEnv("JWT_SECRET", "default-secret-key"));

    ctx.response.redirect(`${getEnv("FRONTEND_URL", "https://this-is-a-test-galaxy--disstella.on.websim.com/")}?token=${jwt}`);

  } catch (error) {
    console.error("认证错误:", error);
    ctx.response.body = "认证失败，请重试。";
    ctx.response.status = 500;
  }
});

router.get("/me", async (ctx) => {
    const authHeader = ctx.request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        ctx.response.status = 401;
        ctx.response.body = { error: "未授权" };
        return;
    }
    const jwt = authHeader.split(" ")[1];
    try {
        const payload = await verify(jwt, getEnv("JWT_SECRET", "default-secret-key"));
        ctx.response.body = { username: payload.username };
    } catch (_error) {
        ctx.response.status = 401;
        ctx.response.body = { error: "无效的凭证" };
    }
});

// --- 启动方舟引擎 (核心变更) ---
const app = new Application();

// 启用CORS中间件
app.use(async (ctx, next) => {
  ctx.response.headers.set("Access-Control-Allow-Origin", "*");
  ctx.response.headers.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  if (ctx.request.method === "OPTIONS") {
    ctx.response.status = 204;
  } else {
    await next();
  }
});

app.use(router.routes());
app.use(router.allowedMethods());

// 【关键改动】我们不再调用 app.listen()，而是监听 fetch 事件
// 这是 Deno Deploy 推荐的标准模式
addEventListener("fetch", (event) => {
  app.handle(event);
});

console.log("方舟引擎核心已准备就绪 (v3)，等待Deno Deploy的请求...");
