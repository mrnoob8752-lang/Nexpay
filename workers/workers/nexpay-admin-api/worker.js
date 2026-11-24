/* NEXPAY API update
 * NEXPAY Admin API Worker
 * Cloudflare Worker + D1 + Firebase Authentication
 *
 * Required Worker bindings:
 *   DB (D1 database: nexpay-db)
 * Required Worker secret:
 *   FIREBASE_API_KEY
 * Required Worker secret:
 *   ADMIN_UID
 * Required Worker variables:
 *   UPI_ID
 *   UPI_QR_URL
 * Optional variable:
 *   APP_ORIGIN = https://nexpay.pruthvirajavhad55.workers.dev
 *
 * Deploy this as the nexpay-admin-api Worker.
 * Existing D1 tables are retained. This Worker creates only its additional
 * payment_orders table and indexes with CREATE TABLE IF NOT EXISTS.
 */
const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function response(data, status = 200, origin = "*") {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...JSON_HEADERS, "access-control-allow-origin": origin,
      "access-control-allow-headers": "Authorization, Content-Type",
      "access-control-allow-methods": "GET, POST, OPTIONS",
      "vary": "Origin" }
  });
}
function fail(message, status = 400) { const e = new Error(message); e.status = status; throw e; }
function uid() { return crypto.randomUUID(); }
function nowIso() { return new Date().toISOString(); }
async function bodyJson(request) {
  try { return await request.json(); } catch { fail("Request body must be valid JSON."); }
}
function integer(value, name, min = 0, max = 100000000) {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < min || n > max) fail("Invalid " + name + ".");
  return n;
}
async function ensureSchema(db) {
  await db.prepare(`CREATE TABLE IF NOT EXISTS payment_orders (
    id TEXT PRIMARY KEY, user_uid TEXT NOT NULL, plan_id TEXT,
    amount_paise INTEGER NOT NULL CHECK(amount_paise > 0),
    payment_reference TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending'
      CHECK(status IN ('pending','approved','rejected')),
    admin_note TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT
  )`).run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_payment_orders_user ON payment_orders(user_uid, created_at)").run();
  await db.prepare("CREATE INDEX IF NOT EXISTS idx_payment_orders_status ON payment_orders(status, created_at)").run();
}
async function authenticate(request, env) {
  const auth = request.headers.get("authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) fail("Sign-in required.", 401);
  if (!env.FIREBASE_API_KEY) fail("Server configuration missing FIREBASE_API_KEY.", 500);
  const result = await fetch("https://identitytoolkit.googleapis.com/v1/accounts:lookup?key=" +
    encodeURIComponent(env.FIREBASE_API_KEY), {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ idToken: match[1] })
    });
  const data = await result.json().catch(() => ({}));
  const user = data.users && data.users[0];
  if (!result.ok || !user || user.disabled === true) fail("Invalid or expired sign-in. Please log in again.", 401);
  return { uid: user.localId, email: (user.email || "").toLowerCase(),
    emailVerified: user.emailVerified === true, displayName: user.displayName || "" };
}
function requireVerified(user) { if (!user.emailVerified) fail("Verify your email before using account features.", 403); }
function requireAdmin(user, env) {
  requireVerified(user);
  if (!env.ADMIN_UID || user.uid !== env.ADMIN_UID ||
      user.email !== "pruthvirajavhad55@gmail.com") fail("Admin access denied.", 403);
}
async function logAdmin(db, user, action, targetType = null, targetId = null, details = null) {
  await db.prepare(`INSERT INTO admin_activity_logs
    (id, admin_uid, action, target_type, target_id, details)
    VALUES (?, ?, ?, ?, ?, ?)`).bind(uid(), user.uid, action, targetType, targetId,
      details ? JSON.stringify(details) : null).run();
}
async function saveUser(db, user) {
  await db.prepare(`INSERT INTO users (uid,email,display_name,email_verified,status)
    VALUES (?,?,?,?, 'active')
    ON CONFLICT(uid) DO UPDATE SET email=excluded.email,
    display_name=excluded.display_name,email_verified=excluded.email_verified,
    updated_at=CURRENT_TIMESTAMP`).bind(user.uid, user.email,
      user.displayName || null, user.emailVerified ? 1 : 0).run();
  const row = await db.prepare("SELECT status FROM users WHERE uid=?").bind(user.uid).first();
  if (row && row.status === "blocked") fail("This account has been blocked. Contact support.", 403);
}
async function balancePaise(db, userUid) {
  const row = await db.prepare(`SELECT COALESCE(SUM(
    CASE
      WHEN type IN ('deposit','reward','referral','adjustment') AND status IN ('approved','completed')
        AND (reference IS NULL OR reference NOT LIKE 'plan:%') THEN amount_paise
      WHEN type='withdrawal' AND status IN ('approved','completed') THEN -amount_paise
      ELSE 0 END),0) AS balance
    FROM transactions WHERE user_uid=?`).bind(userUid).first();
  return Number(row?.balance || 0);
}
async function listRows(db, sql, ...args) {
  const result = await db.prepare(sql).bind(...args).all();
  return result.results || [];
}
async function handle(request, env) {
  if (!env.DB) fail("D1 binding DB is missing.", 500);
  await ensureSchema(env.DB);
  const url = new URL(request.url), path = url.pathname, method = request.method;
  if (method === "GET" && path === "/health") return response({ ok: true, service: "nexpay-admin-api" });
  const user = await authenticate(request, env);
  if (path === "/admin/check" && method === "POST") {
    return response({ ok: true, isAdmin: user.emailVerified &&
      !!env.ADMIN_UID && user.uid === env.ADMIN_UID &&
      user.email === "pruthvirajavhad55@gmail.com" });
  }
  requireVerified(user);
  if (path.startsWith("/admin/")) requireAdmin(user, env);
  else await saveUser(env.DB, user);

  if (path === "/user/profile" && method === "GET") {
    const profile = await env.DB.prepare("SELECT uid,email,display_name,email_verified,status,created_at FROM users WHERE uid=?").bind(user.uid).first();
    return response({ profile, balance_paise: await balancePaise(env.DB, user.uid) });
  }
  if (path === "/user/plans" && method === "GET") {
    const plans = await listRows(env.DB, "SELECT id,name,description,price_paise,duration_days,reward_paise,status FROM plans WHERE status='active' ORDER BY price_paise");
    const activations = await listRows(env.DB, `SELECT a.id,a.plan_id,a.status,a.started_at,a.expires_at,a.created_at,p.name,p.price_paise,p.duration_days
      FROM plan_activations a JOIN plans p ON p.id=a.plan_id WHERE a.user_uid=? ORDER BY a.created_at DESC`, user.uid);
    return response({ plans, activations });
  }
  if (path === "/user/transactions" && method === "GET") {
    const transactions = await listRows(env.DB, "SELECT id,type,amount_paise,status,reference,created_at FROM transactions WHERE user_uid=? ORDER BY created_at DESC LIMIT 100", user.uid);
    return response({ transactions, balance_paise: await balancePaise(env.DB, user.uid) });
  }
  if (path === "/user/payment/settings" && method === "GET") {
    const upiId = String(env.UPI_ID || "").trim();
    const qrUrl = String(env.UPI_QR_URL || "").trim();
    return response({
      configured: !!upiId,
      upi_id: upiId,
      upi_name: String(env.UPI_NAME || "").trim(),
      qr_url: /^https:\/\//i.test(qrUrl) ? qrUrl : ""
    });
  }
  if (path === "/user/payment/submit" && method === "POST") {
    const b = await bodyJson(request);
    const amount = integer(b.amount_paise, "amount_paise", 1, 100000000);
    const reference = String(b.payment_reference || b.reference || "").trim();
    if (reference.length < 4 || reference.length > 120) fail("Enter a valid payment reference.");
    const duplicate = await env.DB.prepare("SELECT id FROM payment_orders WHERE LOWER(payment_reference)=LOWER(?) LIMIT 1").bind(reference).first();
    if (duplicate) fail("This UPI transaction reference has already been submitted. Contact admin if you believe this is an error.", 409);
    let planId = b.plan_id ? String(b.plan_id) : null;
    if (planId) {
      const plan = await env.DB.prepare("SELECT id,price_paise,status FROM plans WHERE id=?").bind(planId).first();
      if (!plan || plan.status !== "active") fail("Selected plan is unavailable.", 404);
      if (Number(plan.price_paise) !== amount) fail("Payment amount does not match the selected plan.");
    }
    const orderId = uid(), txId = uid();
    await env.DB.batch([
      env.DB.prepare("INSERT INTO payment_orders (id,user_uid,plan_id,amount_paise,payment_reference) VALUES (?,?,?,?,?)")
        .bind(orderId, user.uid, planId, amount, reference),
      env.DB.prepare("INSERT INTO transactions (id,user_uid,type,amount_paise,status,reference) VALUES (?,?, 'deposit', ?, 'pending', ?)")
        .bind(txId, user.uid, amount, planId ? "plan:" + orderId : orderId)
    ]);
    return response({ ok: true, order_id: orderId, transaction_id: txId, status: "pending",
      message: "Payment reference submitted for manual review." }, 201);
  }
  if (path === "/user/withdrawals" && method === "GET") {
    const rows = await listRows(env.DB, "SELECT id,amount_paise,payment_reference,status,admin_note,created_at,reviewed_at FROM withdrawal_requests WHERE user_uid=? ORDER BY created_at DESC", user.uid);
    return response({ withdrawals: rows, enabled: false });
  }
  if (path === "/user/withdrawals" && method === "POST") {
    return response({ ok: false, error: "Withdrawals are disabled until the payout workflow is configured and reviewed." }, 403);
  }

  if (path === "/admin/users" && method === "GET") {
    return response({ users: await listRows(env.DB, "SELECT uid,email,display_name,email_verified,status,created_at,updated_at FROM users ORDER BY created_at DESC LIMIT 500") });
  }
  if (path === "/admin/users/status" && method === "POST") {
    const b = await bodyJson(request), target = String(b.uid || b.user_uid || "");
    const status = String(b.status || "");
    if (!target || !["active","blocked"].includes(status)) fail("Provide a valid user UID and status.");
    if (target === user.uid) fail("You cannot change your own admin account status.");
    const r = await env.DB.prepare("UPDATE users SET status=?,updated_at=CURRENT_TIMESTAMP WHERE uid=?").bind(status,target).run();
    if (!r.meta.changes) fail("User not found.",404);
    await logAdmin(env.DB,user,"user_status_changed","user",target,{status});
    return response({ok:true});
  }
  if (path === "/admin/plans" && method === "GET") {
    return response({ plans: await listRows(env.DB,"SELECT * FROM plans ORDER BY created_at DESC") });
  }
  if (path === "/admin/plans" && method === "POST") {
    const b = await bodyJson(request);
    const id = String(b.id || uid()), name = String(b.name || "").trim();
    if (!name || name.length > 80) fail("Plan name is required (maximum 80 characters).");
    const price = integer(b.price_paise,"price_paise",0,100000000);
    const duration = integer(b.duration_days,"duration_days",0,3650);
    const reward = integer(b.reward_paise ?? 0,"reward_paise",0,100000000);
    const status = b.status === "active" ? "active" : "inactive";
    await env.DB.prepare("INSERT INTO plans (id,name,description,price_paise,duration_days,reward_paise,status) VALUES (?,?,?,?,?,?,?)")
      .bind(id,name,String(b.description||"").slice(0,500),price,duration,reward,status).run();
    await logAdmin(env.DB,user,"plan_created","plan",id,{name,price,duration,status});
    return response({ok:true,id},201);
  }
  if (path === "/admin/plans/status" && method === "POST") {
    const b = await bodyJson(request), id = String(b.id || b.plan_id || ""), status = String(b.status || "");
    if (!id || !["active","inactive"].includes(status)) fail("Provide a valid plan ID and status.");
    const r = await env.DB.prepare("UPDATE plans SET status=? WHERE id=?").bind(status,id).run();
    if (!r.meta.changes) fail("Plan not found.",404);
    await logAdmin(env.DB,user,"plan_status_changed","plan",id,{status});
    return response({ok:true});
  }
  if (path === "/admin/transactions" && method === "GET") {
    return response({ transactions: await listRows(env.DB,`SELECT t.*,u.email FROM transactions t LEFT JOIN users u ON u.uid=t.user_uid ORDER BY t.created_at DESC LIMIT 500`) });
  }
  if (path === "/admin/payments" && method === "GET") {
    const payments = await listRows(env.DB, `SELECT po.id,po.user_uid,po.plan_id,po.amount_paise,
      po.payment_reference,po.status,po.admin_note,po.created_at,po.reviewed_at,
      u.email,p.name AS plan_name
      FROM payment_orders po
      LEFT JOIN users u ON u.uid=po.user_uid
      LEFT JOIN plans p ON p.id=po.plan_id
      ORDER BY po.created_at DESC LIMIT 500`);
    return response({ payments });
  }
  if (path === "/admin/payments/review" && method === "POST") {
    const b = await bodyJson(request), orderId = String(b.order_id || b.id || "");
    const status = String(b.status || (b.approve === true ? "approved" : b.approve === false ? "rejected" : ""));
    if (!orderId || !["approved","rejected"].includes(status)) fail("Provide an order ID and approved/rejected status.");
    const order = await env.DB.prepare("SELECT * FROM payment_orders WHERE id=?").bind(orderId).first();
    if (!order) fail("Payment order not found.",404);
    if (order.status !== "pending") fail("This payment has already been reviewed.",409);
    const txRef = order.plan_id ? "plan:" + order.id : order.id;
    const tx = await env.DB.prepare("SELECT id FROM transactions WHERE user_uid=? AND reference=? AND status='pending'").bind(order.user_uid,txRef).first();
    if (!tx) fail("Matching pending transaction not found.",409);
    const note = String(b.admin_note || b.note || "").slice(0,500);
    const ops = [
      env.DB.prepare("UPDATE payment_orders SET status=?,admin_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=? AND status='pending'").bind(status,note,orderId),
      env.DB.prepare("UPDATE transactions SET status=? WHERE id=? AND status='pending'").bind(status,tx.id)
    ];
    if (status === "approved" && order.plan_id) {
      const plan = await env.DB.prepare("SELECT duration_days FROM plans WHERE id=?").bind(order.plan_id).first();
      if (!plan) fail("Plan no longer exists.",409);
      const start = new Date(), end = new Date(start.getTime() + Number(plan.duration_days) * 86400000);
      ops.push(env.DB.prepare("INSERT INTO plan_activations (id,user_uid,plan_id,status,started_at,expires_at) VALUES (?,?,?,'active',?,?)")
        .bind(uid(),order.user_uid,order.plan_id,start.toISOString(),end.toISOString()));
    }
    await env.DB.batch(ops);
    await logAdmin(env.DB,user,"payment_"+status,"payment_order",orderId,{note});
    return response({ok:true,status});
  }
  if (path === "/admin/withdrawals" && method === "GET") {
    return response({ withdrawals: await listRows(env.DB,`SELECT w.*,u.email FROM withdrawal_requests w LEFT JOIN users u ON u.uid=w.user_uid ORDER BY w.created_at DESC LIMIT 500`), enabled:false });
  }
  if (path === "/admin/withdrawals/review" && method === "POST") {
    return response({ok:false,error:"Withdrawal approvals are disabled until a verified payout provider and settlement workflow are configured."},403);
  }
  if (path === "/admin/activity" && method === "GET") {
    return response({ activity: await listRows(env.DB,"SELECT * FROM admin_activity_logs ORDER BY created_at DESC LIMIT 300") });
  }
  return response({ok:false,error:"Route not found."},404);
}
export default {
  async fetch(request, env) {
    const origin = request.headers.get("origin") || "";
    const allowed = env.APP_ORIGIN || "https://nexpay.pruthvirajavhad55.workers.dev";
    if (request.method === "OPTIONS") {
      return new Response(null,{status:204,headers:{
        "access-control-allow-origin":origin===allowed?allowed:allowed,
        "access-control-allow-headers":"Authorization, Content-Type",
        "access-control-allow-methods":"GET, POST, OPTIONS","vary":"Origin"
      }});
    }
    if (new URL(request.url).pathname === "/favicon.ico") {
      return new Response(null, { status: 204, headers: { "access-control-allow-origin": allowed } });
    }
    try {
      const result = await handle(request,env);
      const headers = new Headers(result.headers);
      headers.set("access-control-allow-origin",allowed);
      headers.set("vary","Origin");
      return new Response(result.body,{status:result.status,headers});
    } catch (error) {
      console.error("NEXPAY Worker exception:", error && error.stack ? error.stack : error);
      const status = Number(error.status) || 500;
      const safeMessage = status === 500 ? "Internal server error. Check Worker logs." : error.message;
      return response({
        ok: false,
        error: safeMessage,
        message: safeMessage
      }, status, allowed);
    }
  }
};

// Deployment trigger: configuration update applied in Cloudflare Workers Builds.
