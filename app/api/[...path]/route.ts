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
function stable(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") return Object.fromEntries(Object.keys(value).sort().map((key) => [key, stable((value as Record<string, unknown>)[key])]));
  return value;
}
async function fingerprint(value: unknown) {
  const bytes = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(JSON.stringify(stable(value)))));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
function localKey(localCode: string, local: string) {
  const code = localCode.trim().toUpperCase();
  if (code) return `code:${code}`;
  return `name:${local.trim().normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase()}`;
}
function parseItalianDate(value: string) {
  const m = value.match(/^(\d{2})\/(\d{2})\/(\d{4})(?:\s+(\d{2}):(\d{2})(?::(\d{2}))?)?$/);
  if (!m) return now();
  return new Date(Date.UTC(Number(m[3]), Number(m[2]) - 1, Number(m[1]), Number(m[4] || 0), Number(m[5] || 0), Number(m[6] || 0))).toISOString();
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
      const [machineRows, depositRows, collectorRows, settingRow, localRows] = await Promise.all([
        db().prepare("SELECT * FROM machines ORDER BY local,id").all<Record<string, unknown>>(),
        db().prepare("SELECT id,local,amount,occurred_at AS date,collector,note FROM deposits ORDER BY occurred_at DESC").all<Record<string, unknown>>(),
        db().prepare("SELECT name FROM users WHERE active=1 ORDER BY name").all<{ name: string }>(),
        db().prepare("SELECT value FROM settings WHERE key='company'").first<{ value: string }>(),
        db().prepare("SELECT * FROM local_profiles ORDER BY name").all<Record<string, unknown>>(),
      ]);
      const machines = (machineRows.results || []).map((row) => ({ ...JSON.parse(String(row.raw_json || "{}")), id: row.id, localKey: row.local_key, local: row.local, localCode: row.local_code, pdvCode: row.pdv_code, pdaMac: row.pda_mac, comune: row.comune, provincia: row.provincia, address: row.address, model: row.model, codeModel: row.code_model, codeProvv: row.code_provv, status: row.status, cntIn: row.cnt_in, cntOut: row.cnt_out, exerciseCode: row.exercise_code, hopper1: Number(row.hopper1 || 0), hopper2: Number(row.hopper2 || 0), lastImportId: row.last_import_id }));
      const deposits = (depositRows.results || []).map((row) => ({ ...row, date: row.date, amount: Number(row.amount) }));
      const locals = (localRows.results || []).map((row) => ({ localKey: row.local_key, localCode: row.local_code, pdvCode: row.pdv_code, name: row.name, address: row.address, comune: row.comune, provincia: row.provincia, ragioneSociale: row.ragione_sociale, insegna: row.insegna, partitaIva: row.partita_iva, codiceFiscale: row.codice_fiscale, contactName: row.contact_name, phone: row.phone, email: row.email, pec: row.pec, notes: row.notes, updatedAt: row.updated_at }));
      return json({ machines, deposits, locals, collectors: (collectorRows.results || []).map((u) => u.name), company: settingRow?.value || "Funseven Technology" });
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
      const normalized = rows.filter((m) => m && m.id).map((m) => {
        const item = { id: String(m.id), local: String(m.local || m["DENOMIN. SEDE"] || ""), localCode: String(m.localCode || m["CODICE SEDE"] || ""), pdvCode: String(m.pdvCode || m["CODICE PDV AAMS"] || ""), pdaMac: String(m.pdaMac || m["MACADDRESS PDA"] || ""), comune: String(m.comune || m["COMUNE"] || ""), provincia: String(m.provincia || m["PROVINCIA"] || ""), address: String(m.address || m["INDIRIZZO"] || ""), model: String(m.model || m["MODELLO"] || ""), codeModel: String(m.codeModel || m["CODICE MODELLO"] || ""), codeProvv: String(m.codeProvv || m["CODEID PROVV"] || ""), status: String(m.status || m["DESCR. STATO"] || ""), cntIn: String(m.cntIn || m["CNTTOTIN"] || ""), cntOut: String(m.cntOut || m["CNTTOTOT"] || ""), exerciseCode: String(m.exerciseCode || m["CODICE IS ESERCENTE"] || ""), readAt: parseItalianDate(String(m["DATA ULTIMA LETTURA VAL."] || m.readAt || "")), raw: JSON.stringify(m) };
        return { ...item, localKey: localKey(item.localCode, item.local) };
      });
      if (normalized.length !== rows.length) return json({ error: "Una o più righe non hanno il codice apparecchio." }, 400);
      const batchFingerprint = await fingerprint(normalized.map(({ id, raw }) => ({ id, raw: JSON.parse(raw) })).sort((a, b) => a.id.localeCompare(b.id)));
      const previous = await db().prepare("SELECT id,imported_at AS importedAt,row_count AS rowCount FROM import_batches WHERE fingerprint=?").bind(batchFingerprint).first<{ id: string; importedAt: string; rowCount: number }>();
      if (previous) return json({ duplicate: true, imported: 0, locals: 0, message: "Questo sinottico è già presente nello storico; nessuna modifica effettuata.", previous });
      const batchId = crypto.randomUUID(); const importedAt = now();
      const uniqueLocals = new Map<string, typeof normalized[number]>();
      for (const m of normalized) if (!uniqueLocals.has(m.localKey)) uniqueLocals.set(m.localKey, m);
      try {
        await db().prepare("INSERT INTO import_batches(id,fingerprint,imported_at,imported_by,row_count,local_count) VALUES(?,?,?,?,?,?)")
          .bind(batchId,batchFingerprint,importedAt,auth.user.id,normalized.length,uniqueLocals.size).run();
      } catch {
        const duplicate = await db().prepare("SELECT id,imported_at AS importedAt,row_count AS rowCount FROM import_batches WHERE fingerprint=?").bind(batchFingerprint).first<{ id: string; importedAt: string; rowCount: number }>();
        if (duplicate) return json({ duplicate: true, imported: 0, locals: 0, message: "Questo sinottico è già presente nello storico; nessuna modifica effettuata.", previous: duplicate });
        throw new Error("Non è stato possibile registrare l’importazione.");
      }
      for (const [key, m] of uniqueLocals) await db().prepare(`INSERT INTO local_profiles(local_key,local_code,pdv_code,name,address,comune,provincia,updated_at) VALUES(?,?,?,?,?,?,?,?)
        ON CONFLICT(local_key) DO UPDATE SET local_code=excluded.local_code,pdv_code=excluded.pdv_code,name=excluded.name,address=excluded.address,comune=excluded.comune,provincia=excluded.provincia,updated_at=excluded.updated_at`)
        .bind(key,m.localCode,m.pdvCode,m.local,m.address,m.comune,m.provincia,importedAt).run();
      for (let i = 0; i < normalized.length; i += 35) {
        const statements = normalized.slice(i, i + 35).flatMap((m) => [
          db().prepare(`INSERT INTO machine_history(id,machine_id,import_id,local_key,local,local_code,comune,address,model,code_model,code_provv,status,cnt_in,cnt_out,exercise_code,pda_mac,read_at,raw_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`).bind(crypto.randomUUID(),m.id,batchId,m.localKey,m.local,m.localCode,m.comune,m.address,m.model,m.codeModel,m.codeProvv,m.status,m.cntIn,m.cntOut,m.exerciseCode,m.pdaMac,m.readAt,m.raw),
          db().prepare(`INSERT INTO machines(id,local_key,local,local_code,comune,address,provincia,pdv_code,pda_mac,model,code_model,code_provv,status,cnt_in,cnt_out,exercise_code,last_import_id,raw_json)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET local_key=excluded.local_key,local=excluded.local,local_code=excluded.local_code,comune=excluded.comune,address=excluded.address,provincia=excluded.provincia,pdv_code=excluded.pdv_code,pda_mac=excluded.pda_mac,model=excluded.model,code_model=excluded.code_model,code_provv=excluded.code_provv,status=excluded.status,cnt_in=excluded.cnt_in,cnt_out=excluded.cnt_out,exercise_code=excluded.exercise_code,last_import_id=excluded.last_import_id,raw_json=excluded.raw_json`)
            .bind(m.id,m.localKey,m.local,m.localCode,m.comune,m.address,m.provincia,m.pdvCode,m.pdaMac,m.model,m.codeModel,m.codeProvv,m.status,m.cntIn,m.cntOut,m.exerciseCode,batchId,m.raw),
        ]);
        await db().batch(statements);
      }
      return json({ duplicate: false, imported: normalized.length, locals: uniqueLocals.size, importId: batchId });
    }
    if (method === "GET" && path[0] === "machines" && path[2] === "history") {
      const rows = await db().prepare(`SELECT h.id,h.machine_id AS machineId,h.import_id AS importId,h.local_key AS localKey,h.local,h.local_code AS localCode,h.comune,h.address,h.model,h.code_model AS codeModel,h.code_provv AS codeProvv,h.status,h.cnt_in AS cntIn,h.cnt_out AS cntOut,h.exercise_code AS exerciseCode,h.pda_mac AS pdaMac,h.read_at AS readAt,h.raw_json AS raw,b.imported_at AS importedAt
        FROM machine_history h JOIN import_batches b ON b.id=h.import_id WHERE h.machine_id=? ORDER BY h.read_at DESC,b.imported_at DESC`).bind(path[1]).all<Record<string, unknown>>();
      return json({ history: rows.results || [] });
    }
    if (method === "POST" && path[0] === "machines" && path[2] === "hoppers") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può modificare i fondi hopper." }, 403);
      const { hopper1, hopper2 } = await body<{ hopper1: number; hopper2: number }>(request);
      if (![hopper1,hopper2].every((v) => Number.isFinite(v) && v >= 0 && v <= 1_000_000)) return json({ error: "Importi hopper non validi." }, 400);
      const result = await db().prepare("UPDATE machines SET hopper1=?,hopper2=? WHERE id=?").bind(Math.round(hopper1*100)/100,Math.round(hopper2*100)/100,path[1]).run();
      if (!result.meta.changes) return json({ error: "Apparecchio non trovato." }, 404);
      return json({ ok: true, hopper1, hopper2 });
    }
    if (method === "POST" && path[0] === "locals" && path.length === 2) {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può modificare l’anagrafica dei locali." }, 403);
      const input = await body<Record<string, string>>(request);
      const fields = ["name","address","comune","provincia","ragioneSociale","insegna","partitaIva","codiceFiscale","contactName","phone","email","pec","notes"] as const;
      if (!input.name?.trim()) return json({ error: "Il nome del locale è obbligatorio." }, 400);
      const current = await db().prepare("SELECT local_code AS localCode,pdv_code AS pdvCode FROM local_profiles WHERE local_key=?").bind(decodeURIComponent(path[1])).first<{ localCode: string; pdvCode: string }>();
      const values = Object.fromEntries(fields.map((f) => [f,String(input[f] || "").slice(0, f === "notes" ? 2000 : 200)]));
      await db().prepare(`INSERT INTO local_profiles(local_key,local_code,pdv_code,name,address,comune,provincia,ragione_sociale,insegna,partita_iva,codice_fiscale,contact_name,phone,email,pec,notes,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(local_key) DO UPDATE SET name=excluded.name,address=excluded.address,comune=excluded.comune,provincia=excluded.provincia,ragione_sociale=excluded.ragione_sociale,insegna=excluded.insegna,partita_iva=excluded.partita_iva,codice_fiscale=excluded.codice_fiscale,contact_name=excluded.contact_name,phone=excluded.phone,email=excluded.email,pec=excluded.pec,notes=excluded.notes,updated_at=excluded.updated_at`)
        .bind(decodeURIComponent(path[1]),current?.localCode||"",current?.pdvCode||"",values.name,values.address,values.comune,values.provincia,values.ragioneSociale,values.insegna,values.partitaIva,values.codiceFiscale,values.contactName,values.phone,values.email,values.pec,values.notes,now()).run();
      return json({ ok: true });
    }
    if (method === "GET" && path[0] === "pdas" && path.length === 2) {
      const mac = decodeURIComponent(path[1]);
      const [currentRows,historyRows] = await Promise.all([
        db().prepare("SELECT id,local,local_key AS localKey,model,status,cnt_in AS cntIn,cnt_out AS cntOut FROM machines WHERE pda_mac=? ORDER BY local,id").bind(mac).all(),
        db().prepare("SELECT h.machine_id AS machineId,h.local,h.local_key AS localKey,h.model,h.status,h.cnt_in AS cntIn,h.cnt_out AS cntOut,h.read_at AS readAt,h.import_id AS importId FROM machine_history h WHERE h.pda_mac=? ORDER BY h.read_at DESC").bind(mac).all(),
      ]);
      return json({ mac, machines: currentRows.results || [], history: historyRows.results || [] });
    }
    if (method === "GET" && path.join("/") === "imports") {
      if (!requireAdmin(auth)) return json({ error: "Solo un amministratore può vedere lo storico dei sinottici." }, 403);
      const result = await db().prepare("SELECT b.id,b.imported_at AS importedAt,b.row_count AS rowCount,b.local_count AS localCount,u.name AS importedBy FROM import_batches b JOIN users u ON u.id=b.imported_by ORDER BY b.imported_at DESC").all();
      return json({ imports: result.results || [] });
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
