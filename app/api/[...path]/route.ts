import { env } from "cloudflare:workers";

type User = { id: string; username: string; name: string; role: "admin" | "collector" };
type Db = D1Database;
const COOKIE = "wg_session";
const DAY = 86_400_000;
const encoder = new TextEncoder();
const json = (data: unknown, status = 200, headers: HeadersInit = {}) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store", ...headers } });
const now = () => new Date().toISOString();
const db = () => {
  if (!env.DB) throw new Error("Archivio non configurato");
  return env.DB as Db;
};
const base64url = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
const randomToken = (size = 32) => base64url(crypto.getRandomValues(new Uint8Array(size)));
async function hmac(value: string) {
  const secret = env.WG_SESSION_SECRET;
  if (!secret) throw new Error("Segreto sessione non configurato");
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return base64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}
function cookieValue(request: Request) {
  const raw = request.headers.get("cookie") || "";
  return raw.split(";").map((v) => v.trim()).find((v) => v.startsWith(`${COOKIE}=`))?.slice(COOKIE.length + 1) || "";
}
function cookie(token: string, maxAge: number) {
  return `${COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`;
}
function originOk(request: Request) {
  return request.headers.get("origin") === new URL(request.url).origin;
}
async function identity(request: Request): Promise<{ user: User; deviceId: string | null } | null> {
  const token = cookieValue(request);
  if (!token) return null;
  const tokenHash = await hmac(token);
  const row = await db().prepare(`SELECT u.id,u.username,u.name,u.role,s.device_id AS deviceId,s.expires_at AS expiresAt
    FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND u.active=1`).bind(tokenHash).first<User & { deviceId: string | null; expiresAt: string }>();
  if (!row || row.expiresAt <= now()) return null;
  if (row.deviceId) {
    const device = await db().prepare("SELECT id FROM devices WHERE id=? AND revoked=0").bind(row.deviceId).first();
    if (!device) return null;
    await db().prepare("UPDATE devices SET last_seen_at=? WHERE id=?").bind(now(), row.deviceId).run();
  }
  const { deviceId, expiresAt: _expiresAt, ...user } = row;
  return { user, deviceId };
}
async function createSession(userId: string, deviceId: string | null) {
  const token = randomToken();
  const tokenHash = await hmac(token);
  const expiry = new Date(Date.now() + 30 * DAY).toISOString();
  await db().prepare("INSERT INTO sessions(token_hash,user_id,device_id,expires_at,created_at) VALUES(?,?,?,?,?)")
    .bind(tokenHash, userId, deviceId, expiry, now()).run();
  return { token, expiry };
}
async function passwordHash(password: string, salt?: Uint8Array) {
  const saltBytes = salt || crypto.getRandomValues(new Uint8Array(16));
  const material = await crypto.subtle.importKey("raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations: 100_000 }, material, 256);
  return { salt: base64url(saltBytes), hash: base64url(new Uint8Array(bits)) };
}
const fromB64 = (value: string) => new Uint8Array(atob(value.replaceAll("-", "+").replaceAll("_", "/").padEnd(Math.ceil(value.length / 4) * 4, "=")).split("").map((c) => c.charCodeAt(0)));
async function matchPassword(password: string, salt: string, expected: string) {
  const actual = await passwordHash(password, fromB64(salt));
  if (actual.hash.length !== expected.length) return false;
  let result = 0;
  for (let i = 0; i < expected.length; i++) result |= actual.hash.charCodeAt(i) ^ expected.charCodeAt(i);
  return result === 0;
}
async function rateLimited(request: Request) {
  const address = request.headers.get("cf-connecting-ip") || "unknown";
  const key = await hmac(`rate:${address}`);
  const time = new Date(Date.now() - 10 * 60_000).toISOString();
  const count = await db().prepare("SELECT COUNT(*) AS n FROM auth_attempts WHERE address_hash=? AND created_at>? ").bind(key, time).first<{ n: number }>();
  await db().prepare("INSERT INTO auth_attempts(address_hash,created_at) VALUES(?,?)").bind(key, now()).run();
  if ((count?.n || 0) > 20) return true;
  await db().prepare("DELETE FROM auth_attempts WHERE created_at<?").bind(new Date(Date.now() - DAY).toISOString()).run();
  return false;
}
async function body<T>(request: Request): Promise<T> {
  try { return await request.json() as T; } catch { throw new Error("Richiesta non valida"); }
}
function randomPassword() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%";
  return Array.from(crypto.getRandomValues(new Uint8Array(16)), (n) => chars[n % chars.length]).join("");
}
function requireAdmin(auth: Awaited<ReturnType<typeof identity>>) {
  return !!auth && auth.user.role === "admin";
}

async function handle(request: Request) {
  const path = new URL(request.url).pathname.replace(/^\/api\/?/, "").split("/").filter(Boolean);
  const method = request.method.toUpperCase();
  try {
    if (method === "GET" && path.join("/") === "setup-status") {
      const row = await db().prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
      return json({ needsSetup: (row?.n || 0) === 0 });
    }
    if (method !== "GET" && !originOk(request)) return json({ error: "Origine non autorizzata" }, 403);
    if (method === "POST" && path.join("/") === "setup") {
      if (await rateLimited(request)) return json({ error: "Troppi tentativi. Riprova tra qualche minuto." }, 429);
      const { key, username, name, password } = await body<{ key: string; username: string; name: string; password: string }>(request);
      const boot = env.WG_BOOTSTRAP_KEY;
      if (!boot || key !== boot || !/^[a-zA-Z0-9_.-]{3,32}$/.test(username) || !name?.trim() || password?.length < 12) return json({ error: "Dati non validi o codice iniziale errato." }, 400);
      const result = await db().prepare("SELECT COUNT(*) AS n FROM users").first<{ n: number }>();
      if ((result?.n || 0) !== 0) return json({ error: "Configurazione iniziale già completata." }, 409);
      const id = crypto.randomUUID(); const pw = await passwordHash(password);
      await db().prepare("INSERT INTO users(id,username,name,password_salt,password_hash,role,active,created_at) VALUES(?,?,?,?,?,'admin',1,?)")
        .bind(id, username.toLowerCase(), name.trim(), pw.salt, pw.hash, now()).run();
      const session = await createSession(id, null);
      return json({ user: { id, username: username.toLowerCase(), name: name.trim(), role: "admin" } }, 201, { "Set-Cookie": cookie(session.token, 30 * 86400) });
    }
    if (method === "POST" && path.join("/") === "login") {
      if (await rateLimited(request)) return json({ error: "Troppi tentativi. Riprova tra qualche minuto." }, 429);
      const { username, password } = await body<{ username: string; password: string }>(request);
      const user = await db().prepare("SELECT id,username,name,role,password_salt AS salt,password_hash AS hash FROM users WHERE username=? AND active=1")
        .bind((username || "").trim().toLowerCase()).first<User & { salt: string; hash: string }>();
      if (!user || !(await matchPassword(password || "", user.salt, user.hash))) return json({ error: "Nome utente o password non corretti." }, 401);
      const session = await createSession(user.id, null);
      const { salt: _salt, hash: _hash, ...publicUser } = user;
      return json({ user: publicUser }, 200, { "Set-Cookie": cookie(session.token, 30 * 86400) });
    }
    if (method === "POST" && path.join("/") === "pair") {
      if (await rateLimited(request)) return json({ error: "Troppi tentativi. Riprova tra qualche minuto." }, 429);
      const { code, label } = await body<{ code: string; label?: string }>(request);
      const normalized = (code || "").replace(/\s/g, "");
      if (!/^\d{8}$/.test(normalized)) return json({ error: "Il codice deve contenere 8 cifre." }, 400);
      const codeHash = await hmac(`pair:${normalized}`);
      const usedAt = now();
      const claimed = await db().prepare(`UPDATE pair_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at>? RETURNING user_id`)
        .bind(usedAt, codeHash, usedAt).first<{ user_id: string }>();
      if (!claimed) return json({ error: "Codice scaduto o già utilizzato." }, 401);
      const id = crypto.randomUUID(); const stamp = now();
      await db().prepare("INSERT INTO devices(id,user_id,label,created_at,last_seen_at,revoked) VALUES(?,?,?,?,?,0)")
        .bind(id, claimed.user_id, (label || "Telefono").slice(0, 80), stamp, stamp).run();
      const session = await createSession(claimed.user_id, id);
      const user = await db().prepare("SELECT id,username,name,role FROM users WHERE id=? AND active=1").bind(claimed.user_id).first<User>();
      if (!user) return json({ error: "Utente non attivo." }, 401);
      return json({ user }, 200, { "Set-Cookie": cookie(session.token, 30 * 86400) });
    }
    if (method === "GET" && path.join("/") === "me") {
      const auth = await identity(request);
      return json({ user: auth?.user || null, needsSetup: false });
    }
    const auth = await identity(request);
    if (!auth) return json({ error: "Accesso richiesto." }, 401);
    if (method === "POST" && path.join("/") === "logout") {
      await db().prepare("DELETE FROM sessions WHERE token_hash=?").bind(await hmac(cookieValue(request))).run();
      return json({ ok: true }, 200, { "Set-Cookie": cookie("", 0) });
    }
    if (method === "GET" && path.join("/") === "data") {
      const [machineRows, depositRows, collectorRows, settingRow] = await Promise.all([
        db().prepare("SELECT * FROM machines ORDER BY local,id").all<Record<string, unknown>>(),
        db().prepare("SELECT id,local,amount,occurred_at AS date,collector,note FROM deposits ORDER BY occurred_at DESC").all<Record<string, unknown>>(),
        db().prepare("SELECT name FROM users WHERE active=1 ORDER BY name").all<{ name: string }>(),
        db().prepare("SELECT value FROM settings WHERE key='company'").first<{ value: string }>(),
      ]);
      const machines = (machineRows.results || []).map((row) => ({ ...JSON.parse(String(row.raw_json || "{}")), id: row.id, local: row.local, comune: row.comune, address: row.address, model: row.model, codeModel: row.code_model, codeProvv: row.code_provv, status: row.status, cntIn: row.cnt_in, cntOut: row.cnt_out, exerciseCode: row.exercise_code }));
      const deposits = (depositRows.results || []).map((row) => ({ ...row, date: row.date, amount: Number(row.amount) }));
      return json({ machines, deposits, collectors: (collectorRows.results || []).map((u) => u.name), company: settingRow?.value || "Funseven Technology" });
    }
    if (method === "POST" && path.join("/") === "deposits") {
      const { local, amount, note } = await body<{ local: string; amount: number; note?: string }>(request);
      if (!local?.trim() || !Number.isFinite(amount) || amount <= 0 || amount > 1_000_000) return json({ error: "Locale o importo non valido." }, 400);
      const deposit = { id: crypto.randomUUID(), local: local.trim(), amount: Math.round(amount * 100) / 100, date: now(), collector: auth.user.name, note: (note || "").slice(0, 500) };
      await db().prepare("INSERT INTO deposits(id,local,amount,occurred_at,collector,note,created_by) VALUES(?,?,?,?,?,?,?)")
        .bind(deposit.id, deposit.local, deposit.amount, deposit.date, deposit.collector, deposit.note, auth.user.id).run();
      return json({ deposit }, 201);
    }
    if (method === "POST" && path.join("/") === "machines/import") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può importare il sinottico." }, 403);
      const { rows } = await body<{ rows: Record<string, string>[] }>(request);
      if (!Array.isArray(rows) || rows.length > 10_000) return json({ error: "File troppo grande o non valido." }, 400);
      const normalized = rows.filter((m) => m && m.id).map((m) => ({ id: String(m.id), local: String(m.local || ""), comune: String(m.comune || ""), address: String(m.address || ""), model: String(m.model || ""), codeModel: String(m.codeModel || ""), codeProvv: String(m.codeProvv || ""), status: String(m.status || ""), cntIn: String(m.cntIn || ""), cntOut: String(m.cntOut || ""), exerciseCode: String(m.exerciseCode || ""), raw: JSON.stringify(m) }));
      if (normalized.length !== rows.length) return json({ error: "Una o più righe non hanno il codice apparecchio." }, 400);
      for (let i = 0; i < normalized.length; i += 60) {
        const statements = normalized.slice(i, i + 60).map((m) => db().prepare(`INSERT INTO machines(id,local,comune,address,model,code_model,code_provv,status,cnt_in,cnt_out,exercise_code,raw_json)
          VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET local=excluded.local,comune=excluded.comune,address=excluded.address,model=excluded.model,code_model=excluded.code_model,code_provv=excluded.code_provv,status=excluded.status,cnt_in=excluded.cnt_in,cnt_out=excluded.cnt_out,exercise_code=excluded.exercise_code,raw_json=excluded.raw_json`)
          .bind(m.id,m.local,m.comune,m.address,m.model,m.codeModel,m.codeProvv,m.status,m.cntIn,m.cntOut,m.exerciseCode,m.raw));
        await db().batch(statements);
      }
      const ids = normalized.map((m) => m.id);
      if (ids.length) await db().prepare(`DELETE FROM machines WHERE id NOT IN (${ids.map(() => "?").join(",")})`).bind(...ids).run();
      else await db().prepare("DELETE FROM machines").run();
      return json({ imported: normalized.length, locals: new Set(normalized.map((m) => m.local)).size });
    }
    if (method === "POST" && path.join("/") === "company") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può cambiare le impostazioni." }, 403);
      const { company } = await body<{ company: string }>(request);
      if (!company?.trim() || company.length > 100) return json({ error: "Nome azienda non valido." }, 400);
      await db().prepare("INSERT INTO settings(key,value) VALUES('company',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(company.trim()).run();
      return json({ ok: true });
    }
    if (method === "GET" && path.join("/") === "users") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può gestire gli utenti." }, 403);
      const result = await db().prepare("SELECT id,username,name,role,active,created_at AS createdAt FROM users ORDER BY name").all();
      return json({ users: result.results || [] });
    }
    if (method === "POST" && path.join("/") === "users") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può creare utenti." }, 403);
      const { username, name, role } = await body<{ username: string; name: string; role: string }>(request);
      const normalized = (username || "").trim().toLowerCase();
      if (!/^[a-z0-9_.-]{3,32}$/.test(normalized) || !name?.trim() || !["admin", "collector"].includes(role)) return json({ error: "Controlla nome, utente e ruolo." }, 400);
      const password = randomPassword(); const pw = await passwordHash(password); const id = crypto.randomUUID();
      try {
        await db().prepare("INSERT INTO users(id,username,name,password_salt,password_hash,role,active,created_at) VALUES(?,?,?,?,?,?,1,?)")
          .bind(id, normalized, name.trim(), pw.salt, pw.hash, role, now()).run();
      } catch { return json({ error: "Nome utente già presente." }, 409); }
      return json({ user: { id, username: normalized, name: name.trim(), role }, temporaryPassword: password }, 201);
    }
    if (method === "POST" && path[0] === "users" && path[2] === "disable") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può disattivare utenti." }, 403);
      const userId = path[1];
      if (userId === auth.user.id) return json({ error: "Non puoi disattivare il tuo account." }, 400);
      await db().batch([
        db().prepare("UPDATE users SET active=0 WHERE id=?").bind(userId),
        db().prepare("DELETE FROM sessions WHERE user_id=?").bind(userId),
      ]);
      return json({ ok: true });
    }
    if (method === "POST" && path.join("/") === "pair-codes") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può generare i codici." }, 403);
      const { userId } = await body<{ userId: string }>(request);
      const target = await db().prepare("SELECT id FROM users WHERE id=? AND active=1").bind(userId).first();
      if (!target) return json({ error: "Utente non trovato." }, 404);
      const raw = String(crypto.getRandomValues(new Uint32Array(1))[0] % 100_000_000).padStart(8, "0");
      const expiresAt = new Date(Date.now() + 5 * 60_000).toISOString();
      await db().prepare("INSERT INTO pair_codes(code_hash,user_id,created_by,expires_at,used_at) VALUES(?,?,?,?,NULL)")
        .bind(await hmac(`pair:${raw}`), userId, auth.user.id, expiresAt).run();
      return json({ code: raw, expiresAt });
    }
    if (method === "GET" && path.join("/") === "devices") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può gestire i dispositivi." }, 403);
      const rows = await db().prepare("SELECT d.id,d.label,d.created_at AS createdAt,d.last_seen_at AS lastSeenAt,u.name,u.username FROM devices d JOIN users u ON u.id=d.user_id WHERE d.revoked=0 ORDER BY d.last_seen_at DESC").all();
      return json({ devices: rows.results || [] });
    }
    if (method === "POST" && path[0] === "devices" && path[2] === "revoke") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può revocare dispositivi." }, 403);
      await db().batch([
        db().prepare("UPDATE devices SET revoked=1 WHERE id=?").bind(path[1]),
        db().prepare("DELETE FROM sessions WHERE device_id=?").bind(path[1]),
      ]);
      return json({ ok: true });
    }
    return json({ error: "Funzione non trovata." }, 404);
  } catch (error) {
    console.error("WinGames API error", error);
    return json({ error: error instanceof Error ? error.message : "Errore interno." }, 500);
  }
}

export const GET = (request: Request) => handle(request);
export const POST = (request: Request) => handle(request);
