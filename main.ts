import { Application, Router } from "https://deno.land/x/oak@v12.6.1/mod.ts";
import { OAuth2Client } from "https://deno.land/x/oauth2_client@v1.0.2/mod.ts";
import { create, verify } from "https://deno.land/x/djwt@v2.9.1/mod.ts";

// --- 环境变量现在在需要时才获取，这能更好地兼容Deno Deploy的启动流程 ---
const getEnv = (key: string, defaultValue: string = "") => Deno.env.get(key) || defaultValue;

// --- OAuth2 客户端配置现在变成一个函数，在路由被调用时才执行 ---
function createOAuth2Client() {
  return new OAuth2Client({
    clientId: getEnv("LINUX_DO_CLIENT_ID"),
    clientSecret: getEnv("LINUX_DO_CLIENT_SECRET"),
    authorizationEndpointUri: "https://connect.linux.do/oauth2/authorize",
    tokenUri: "https://connect.linux.do/oauth2/token",
    // ✅ 这里的地址是正确的，它会从环境变量中读取
    redirectUri: `${getEnv("DEPLOYMENT_URL")}/auth/callback`,
    defaults: {
      scope: "read",
    },
  });
}

// --- 创建方舟的路由系统 ---
const router = new Router();

// 路由1: /login - 引导用户去Linux.do星门
router.get("/login", (ctx) => {
  const oauth2Client = createOAuth2Client(); // 在这里才创建客户端实例
  const authUrl = oauth2Client.code.getAuthorizationUri();
  ctx.response.redirect(authUrl);
});

// 路由2: /auth/callback - 接收Linux.do星门返回的信号
router.get("/auth/callback", async (ctx) => {
  const oauth2Client = createOAuth2Client(); // 在这里也重新创建
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
    const jwt = await create({ alg: "HS256", typ: "JWT" }, payload, getEnv("JWT_SECRET", "default-secret-key"));

    ctx.response.redirect(`${getEnv("FRONTEND_URL", "https://this-is-a-test-galaxy--disstella.on.websim.com/")}?token=${jwt}`);

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
        const payload = await verify(jwt, getEnv("JWT_SECRET", "default-secret-key"));
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

console.log("方舟引擎核心已启动 (v2)，正在监听8000端口...");
await app.listen({ port: 8000 });
