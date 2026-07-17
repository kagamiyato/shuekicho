/**
 * 収益帳 Pro 会員判定Worker
 *
 * ルーティング:
 *   POST /webhook/stripe   ... Stripeからのイベント通知を受け取る
 *   GET  /api/check-pro    ... サイトからメールアドレスで会員確認する
 *   それ以外                ... 静的サイト（index.html等）をそのまま配信する
 *
 * 保存するデータ（KV: PRO_MEMBERS）:
 *   member:<email>    -> { status: "active" | "canceled", updated: <epoch ms> }
 *   customer:<cus_id> -> <email>   （解約イベント時にメールへ逆引きするため）
 *
 * 重要：ここで保存するのはメールアドレスと会員ステータスのみです。
 * CSVの中身（収益データ）はこのWorkerを一切経由しません。
 */

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === "/webhook/stripe" && request.method === "POST") {
      return handleStripeWebhook(request, env);
    }

    if (url.pathname === "/api/check-pro" && request.method === "GET") {
      return handleCheckPro(request, env);
    }

    // それ以外は静的アセット（index.html等）をそのまま返す
    return env.ASSETS.fetch(request);
  },
};

// ---------- Pro会員確認 ----------

async function handleCheckPro(request, env) {
  const url = new URL(request.url);
  const rawEmail = (url.searchParams.get("email") || "").trim().toLowerCase();

  const corsHeaders = { "Content-Type": "application/json; charset=utf-8" };

  if (!rawEmail || !isValidEmail(rawEmail)) {
    return new Response(JSON.stringify({ pro: false, error: "invalid_email" }), {
      status: 400,
      headers: corsHeaders,
    });
  }

  const record = await env.PRO_MEMBERS.get("member:" + rawEmail);
  let pro = false;
  if (record) {
    try {
      const parsed = JSON.parse(record);
      pro = parsed.status === "active";
    } catch (e) {
      pro = false;
    }
  }

  return new Response(JSON.stringify({ pro }), { status: 200, headers: corsHeaders });
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---------- Stripe Webhook ----------

async function handleStripeWebhook(request, env) {
  const signatureHeader = request.headers.get("stripe-signature");
  const rawBody = await request.text();

  if (!signatureHeader) {
    return new Response("Missing signature", { status: 400 });
  }

  const verified = await verifyStripeSignature(rawBody, signatureHeader, env.STRIPE_WEBHOOK_SECRET);
  if (!verified) {
    return new Response("Invalid signature", { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (e) {
    return new Response("Invalid JSON", { status: 400 });
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object;
        const email = (session.customer_details && session.customer_details.email) || session.customer_email;
        const customerId = session.customer;
        if (email && customerId) {
          const normalized = email.trim().toLowerCase();
          await env.PRO_MEMBERS.put("customer:" + customerId, normalized);
          await env.PRO_MEMBERS.put(
            "member:" + normalized,
            JSON.stringify({ status: "active", updated: Date.now() })
          );
        }
        break;
      }
      case "customer.subscription.updated": {
        const sub = event.data.object;
        const email = await env.PRO_MEMBERS.get("customer:" + sub.customer);
        if (email) {
          const active = sub.status === "active" || sub.status === "trialing";
          await env.PRO_MEMBERS.put(
            "member:" + email,
            JSON.stringify({ status: active ? "active" : "canceled", updated: Date.now() })
          );
        }
        break;
      }
      case "customer.subscription.deleted": {
        const sub = event.data.object;
        const email = await env.PRO_MEMBERS.get("customer:" + sub.customer);
        if (email) {
          await env.PRO_MEMBERS.put(
            "member:" + email,
            JSON.stringify({ status: "canceled", updated: Date.now() })
          );
        }
        break;
      }
      default:
        // 未対応のイベントは無視してOK
        break;
    }
  } catch (e) {
    // Stripeには200を返しつつ、内部エラーは握りつぶさずログに残す
    console.error("webhook handling error", e);
  }

  return new Response(JSON.stringify({ received: true }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

async function verifyStripeSignature(payload, sigHeader, secret) {
  if (!secret) return false;

  const parts = {};
  sigHeader.split(",").forEach((part) => {
    const [k, v] = part.split("=");
    parts[k] = v;
  });

  const timestamp = parts.t;
  const signature = parts.v1;
  if (!timestamp || !signature) return false;

  // リプレイ攻撃対策：5分以上古いイベントは拒否
  const nowSeconds = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSeconds - Number(timestamp)) > 300) return false;

  const signedPayload = `${timestamp}.${payload}`;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(signedPayload));
  const expected = [...new Uint8Array(sigBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");

  return timingSafeEqual(expected, signature);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return result === 0;
}
