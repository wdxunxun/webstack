// Cloudflare Pages Function: 全站 HTTP Basic 密码保护
// 优先使用环境变量 NAV_PASSWORD（在 Cloudflare 面板设置，不会进入仓库）；
// 未设置时回退到内置哈希，仅作"防顺手点进来"的弱保护。
//
// 设置真密码：Cloudflare 面板 → Pages → 本项目 → Settings → Environment variables
//            新增 NAV_PASSWORD（加密变量），然后重新部署一次。

const FALLBACK_SHA256 = "36b0579be6ce0528cba609ec39bc78eae29c483cf78280666fc4d3584f107079"; // sha256("301111")

function toHex(buf) {
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
}

function safeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function passwordMatches(given, env) {
  const configured = env && env.NAV_PASSWORD;
  if (configured) return safeEqual(given, configured);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(given));
  return safeEqual(toHex(digest), FALLBACK_SHA256);
}

function unauthorized() {
  return new Response("需要密码访问\n", {
    status: 401,
    headers: {
      "WWW-Authenticate": 'Basic realm="WebStack", charset="UTF-8"',
      "Content-Type": "text/plain; charset=utf-8",
      "Cache-Control": "no-store",
    },
  });
}

export async function onRequest(context) {
  const { request, env, next } = context;
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Basic ")) return unauthorized();

  let decoded;
  try {
    decoded = atob(auth.slice(6));
  } catch {
    return unauthorized();
  }
  const sep = decoded.indexOf(":");
  if (sep < 0) return unauthorized();
  const password = decoded.slice(sep + 1);

  if (!(await passwordMatches(password, env))) return unauthorized();

  const response = await next();
  const out = new Response(response.body, response);
  out.headers.set("Cache-Control", "private, no-store");
  return out;
}
