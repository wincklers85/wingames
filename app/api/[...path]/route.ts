import { env } from "cloudflare:workers";

type User = { id: string; username: string; name: string; role: "admin" | "collector" };
type Db = D1Database;
const COOKIE = "wg_session";
const DAY = 86_400_000;
const encoder = new TextEncoder();
const json = (data: unknown, status = 200, headers: HeadersInit = {}) =>
  Response.json(data, { status, headers: { "Cache-Control": "no-store", ...headers } });
const now = () => new Date().toISOString();
const businessDate = () => new Date().toLocaleDateString("sv-SE", { timeZone: "Europe/Rome" });
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
      const [machineRows, depositRows, collectorRows, settingRow, localRows, financeRows] = await Promise.all([
        db().prepare("SELECT * FROM machines ORDER BY local,id").all<Record<string, unknown>>(),
        db().prepare("SELECT id,local,amount,occurred_at AS date,collector,note FROM deposits ORDER BY occurred_at DESC").all<Record<string, unknown>>(),
        db().prepare("SELECT name FROM users WHERE active=1 ORDER BY name").all<{ name: string }>(),
        db().prepare("SELECT value FROM settings WHERE key='company'").first<{ value: string }>(),
        db().prepare("SELECT * FROM local_profiles ORDER BY name").all<Record<string, unknown>>(),
        db().prepare("SELECT key,value FROM settings WHERE key IN ('preu_percent','aams_percent','service_enabled','service_percent','counter_tolerance','company_address','company_vat','company_cf')").all<{key:string;value:string}>(),
      ]);
      const machines = (machineRows.results || []).map((row) => ({ ...JSON.parse(String(row.raw_json || "{}")), id: row.id, localKey: row.local_key, local: row.local, localCode: row.local_code, pdvCode: row.pdv_code, pdaMac: row.pda_mac, comune: row.comune, provincia: row.provincia, address: row.address, model: row.model, codeModel: row.code_model, codeProvv: row.code_provv, status: row.status, cntIn: row.cnt_in, cntOut: row.cnt_out, exerciseCode: row.exercise_code, hopper1: Number(row.hopper1 || 0), hopper2: Number(row.hopper2 || 0), lastImportId: row.last_import_id }));
      const deposits = (depositRows.results || []).map((row) => ({ ...row, date: row.date, amount: Number(row.amount) }));
      const locals = (localRows.results || []).map((row) => ({ localKey: row.local_key, localCode: row.local_code, pdvCode: row.pdv_code, name: row.name, address: row.address, comune: row.comune, provincia: row.provincia, ragioneSociale: row.ragione_sociale, insegna: row.insegna, partitaIva: row.partita_iva, codiceFiscale: row.codice_fiscale, contactName: row.contact_name, phone: row.phone, email: row.email, pec: row.pec, notes: row.notes, retePercent: Number(row.rete_percent ?? 1), exercisePercent: Number(row.exercise_percent ?? 50), updatedAt: row.updated_at }));
      const finance = Object.fromEntries((financeRows.results||[]).map(x=>[x.key,x.value]));
      return json({ machines, deposits, locals, collectors: (collectorRows.results || []).map((u) => u.name), company: settingRow?.value || "Funseven Technology", companyFiscal:{address:String(finance.company_address||""),vat:String(finance.company_vat||""),fiscalCode:String(finance.company_cf||"")}, finance:{preuPercent:Number(finance.preu_percent??24),aamsPercent:Number(finance.aams_percent??0.8),serviceEnabled:finance.service_enabled==='1',servicePercent:Number(finance.service_percent??50),counterTolerance:Number(finance.counter_tolerance??100)} });
    }
    if (method === "GET" && path[0] === "collection-board" && path[1]) {
      const key=decodeURIComponent(path[1]);
      const [localRow,machineRows,depositRow,visitRow,financeRows]=await Promise.all([
        db().prepare("SELECT * FROM local_profiles WHERE local_key=?").bind(key).first<Record<string,unknown>>(),
        db().prepare(`SELECT m.id,m.local,m.model,m.cnt_in AS cntIn,m.cnt_out AS cntOut,m.hopper1,m.hopper2,m.raw_json AS raw,
          COALESCE((SELECT mc.global_in FROM machine_collections mc JOIN collection_visits v ON v.id=mc.visit_id WHERE mc.machine_id=m.id AND v.status='closed' ORDER BY v.closed_at DESC LIMIT 1),CAST(NULLIF(m.cnt_in,'') AS REAL),0) AS baseIn,
          COALESCE((SELECT mc.global_out FROM machine_collections mc JOIN collection_visits v ON v.id=mc.visit_id WHERE mc.machine_id=m.id AND v.status='closed' ORDER BY v.closed_at DESC LIMIT 1),CAST(NULLIF(m.cnt_out,'') AS REAL),0) AS baseOut
          FROM machines m WHERE m.local_key=? ORDER BY m.id`).bind(key).all<Record<string,unknown>>(),
        db().prepare(`SELECT COALESCE(SUM(amount),0) AS total FROM deposits WHERE local=? AND occurred_at>COALESCE((SELECT MAX(closed_at) FROM collection_visits WHERE local_key=? AND status='closed'),'1970-01-01T00:00:00.000Z')`).bind((await db().prepare("SELECT name FROM local_profiles WHERE local_key=?").bind(key).first<{name:string}>())?.name||"",key).first<{total:number}>(),
        db().prepare("SELECT id,local,status,payment_method AS paymentMethod,started_at AS startedAt,deposits,totals_json AS totalsJson FROM collection_visits WHERE local_key=? AND status='open' ORDER BY started_at DESC LIMIT 1").bind(key).first<Record<string,unknown>>(),
        db().prepare("SELECT key,value FROM settings WHERE key IN ('preu_percent','aams_percent','service_enabled','service_percent','counter_tolerance')").all<{key:string;value:string}>(),
      ]);
      if(!localRow)return json({error:"Locale non trovato."},404);
      const readingRows=visitRow?(await db().prepare("SELECT id,visit_id AS visitId,machine_id AS machineId,model,partial_in AS partialIn,partial_out AS partialOut,global_in AS globalIn,global_out AS globalOut,manual_counters AS manualCounters,drawer,taxes,net_drawer AS netDrawer,manager_share AS managerShare,exercise_share AS exerciseShare,service_share AS serviceShare,created_at AS createdAt FROM machine_collections WHERE visit_id=? ORDER BY created_at").bind(visitRow.id).all<Record<string,unknown>>()).results||[]:[];
      const visit=visitRow?{...visitRow,readings:readingRows,totals:JSON.parse(String(visitRow.totalsJson||"{}"))}:null;
      const f=Object.fromEntries((financeRows.results||[]).map(x=>[x.key,Number(x.value)]));
      return json({local:{localKey:key,name:localRow.name,insegna:localRow.insegna,ragioneSociale:localRow.ragione_sociale,partitaIva:localRow.partita_iva,codiceFiscale:localRow.codice_fiscale,phone:localRow.phone,email:localRow.email,address:localRow.address,comune:localRow.comune,provincia:localRow.provincia,retePercent:Number(localRow.rete_percent??1),exercisePercent:Number(localRow.exercise_percent??50)},machines:machineRows.results||[],deposits:Number(depositRow?.total||0),visit,finance:{preuPercent:f.preu_percent??24,aamsPercent:f.aams_percent??0.8,serviceEnabled:f.service_enabled===1,servicePercent:f.service_percent??50,counterTolerance:f.counter_tolerance??100}});
    }
    if(method==="POST"&&path.join("/")==="collections/start"){
      const {localKey:key}=await body<{localKey:string}>(request);const profile=await db().prepare("SELECT name FROM local_profiles WHERE local_key=?").bind(key).first<{name:string}>();if(!profile)return json({error:"Locale non trovato."},404);
      if(await db().prepare("SELECT id FROM day_closings WHERE day=? AND status='closed'").bind(businessDate()).first())return json({error:"La giornata è già stata chiusa. Chiedi all’amministratore di riaprirla."},409);
      const active=await db().prepare("SELECT id FROM collection_visits WHERE local_key=? AND status='open'").bind(key).first();if(active)return json({error:"Esiste già un incasso aperto per questo locale."},409);
      const id=crypto.randomUUID(),stamp=now();const prior=await db().prepare("SELECT MAX(closed_at) AS last FROM collection_visits WHERE local_key=? AND status='closed'").bind(key).first<{last:string|null}>();const outstanding=await db().prepare("SELECT COALESCE(SUM(amount),0) AS total FROM deposits WHERE local=? AND occurred_at>? ").bind(profile.name,prior?.last||"1970-01-01T00:00:00.000Z").first<{total:number}>();
      await db().prepare("INSERT INTO collection_visits(id,local_key,local,status,payment_method,business_day,started_at,collector_id,collector_name,deposits) VALUES(?,?,?,'open','cash',?,?,?,?,?)").bind(id,key,profile.name,businessDate(),stamp,auth.user.id,auth.user.name,Number(outstanding?.total||0)).run();return json({id,local:profile.name,startedAt:stamp,deposits:Number(outstanding?.total||0)},201);
    }
    if(method==="POST"&&path[0]==="collections"&&path[2]==="readings"&&path.length===3){
      const visitId=path[1],input=await body<{machineId:string;partialIn:number;partialOut:number;globalIn?:number;globalOut?:number;manualCounters?:boolean}>(request);const visit=await db().prepare("SELECT local_key AS localKey,status FROM collection_visits WHERE id=?").bind(visitId).first<{localKey:string;status:string}>();if(!visit||visit.status!=="open")return json({error:"Incasso non aperto."},409);
      const m=await db().prepare("SELECT id,model,cnt_in AS cntIn,cnt_out AS cntOut,local_key AS localKey FROM machines WHERE id=?").bind(input.machineId).first<{id:string;model:string;cntIn:string;cntOut:string;localKey:string}>();if(!m||m.localKey!==visit.localKey)return json({error:"La macchina non appartiene a questo locale."},400);
      if(![input.partialIn,input.partialOut].every(v=>Number.isFinite(v)&&v>=0&&v<=100000000))return json({error:"Parziali non validi."},400);
      const previous=await db().prepare("SELECT mc.global_in AS globalIn,mc.global_out AS globalOut FROM machine_collections mc JOIN collection_visits v ON v.id=mc.visit_id WHERE mc.machine_id=? AND v.status='closed' ORDER BY v.closed_at DESC LIMIT 1").bind(m.id).first<{globalIn:number;globalOut:number}>();const baseIn=Number(previous?.globalIn??(m.cntIn||0)),baseOut=Number(previous?.globalOut??(m.cntOut||0));const expectedIn=baseIn+input.partialIn,expectedOut=baseOut+input.partialOut;const manual=!!input.manualCounters;const globalIn=manual?Number(input.globalIn):expectedIn,globalOut=manual?Number(input.globalOut):expectedOut;if(![globalIn,globalOut].every(v=>Number.isFinite(v)&&v>=0))return json({error:"Contatori globali non validi."},400);
      const [local,settingsRows]=await Promise.all([db().prepare("SELECT rete_percent AS retePercent,exercise_percent AS exercisePercent FROM local_profiles WHERE local_key=?").bind(visit.localKey).first<{retePercent:number;exercisePercent:number}>(),db().prepare("SELECT key,value FROM settings WHERE key IN ('preu_percent','aams_percent','service_enabled','service_percent','counter_tolerance')").all<{key:string;value:string}>()]);const f=Object.fromEntries((settingsRows.results||[]).map(x=>[x.key,Number(x.value)]));const rete=Number(local?.retePercent??1),exercisePct=Number(local?.exercisePercent??50),preu=f.preu_percent??24,aams=f.aams_percent??0.8;const round=(v:number)=>Math.round((v+Number.EPSILON)*100)/100;const drawer=round(input.partialIn-input.partialOut),taxes=round(input.partialIn*(preu+aams+rete)/100),netDrawer=round(drawer-taxes),exerciseShare=round(netDrawer*exercisePct/100),managerShare=round(netDrawer-exerciseShare),serviceShare=f.service_enabled===1?round(managerShare*(f.service_percent??50)/100):0;const id=crypto.randomUUID();
      await db().prepare(`INSERT INTO machine_collections(id,visit_id,machine_id,model,partial_in,partial_out,global_in,global_out,manual_counters,drawer,taxes,net_drawer,manager_share,exercise_share,service_share,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`).bind(id,visitId,m.id,m.model,input.partialIn,input.partialOut,globalIn,globalOut,manual?1:0,drawer,taxes,netDrawer,managerShare,exerciseShare,serviceShare,now()).run();
      const old=await db().prepare("SELECT id FROM machine_collections WHERE visit_id=? AND machine_id=? AND id<>?").bind(visitId,m.id,id).all<{id:string}>();if(old.results?.length){await db().prepare("DELETE FROM machine_collections WHERE visit_id=? AND machine_id=? AND id<>?").bind(visitId,m.id,id).run()}
      const tolerance=f.counter_tolerance??100;const synopticIn=Number(m.cntIn||0)+input.partialIn,synopticOut=Number(m.cntOut||0)+input.partialOut;if(manual||Math.abs(globalIn-synopticIn)>tolerance||Math.abs(globalOut-synopticOut)>tolerance){const message=manual?`Contatori globali modificati manualmente: ${m.id} (${globalIn}/${globalOut}); automatici ${expectedIn}/${expectedOut}.`:`Incongruenza contatori ${m.id}: rilevati ${globalIn}/${globalOut}, sinottico atteso ${synopticIn}/${synopticOut}.`;await db().prepare("INSERT INTO alerts(id,kind,message,local_key,machine_id,created_by,created_by_name,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),manual?"manual_counter":"counter_mismatch",message,visit.localKey,m.id,auth.user.id,auth.user.name,now()).run()}
      return json({reading:{id,visitId,machineId:m.id,model:m.model,partialIn:input.partialIn,partialOut:input.partialOut,globalIn,globalOut,manualCounters:manual,drawer,taxes,netDrawer,managerShare,exerciseShare,serviceShare,createdAt:now()}});
    }
    if(method==="POST"&&path[0]==="collections"&&path[2]==="readings"&&path[3]){
      const row=await db().prepare("SELECT mc.machine_id AS machineId,v.local_key AS localKey FROM machine_collections mc JOIN collection_visits v ON v.id=mc.visit_id WHERE mc.id=? AND v.status='open'").bind(path[3]).first<{machineId:string;localKey:string}>();if(!row)return json({error:"Lettura non trovata o incasso già chiuso."},404);await db().prepare("DELETE FROM machine_collections WHERE id=?").bind(path[3]).run();await db().prepare("INSERT INTO alerts(id,kind,message,local_key,machine_id,created_by,created_by_name,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(crypto.randomUUID(),"reading_deleted",`Lettura incasso annullata per ${row.machineId}.`,row.localKey,row.machineId,auth.user.id,auth.user.name,now()).run();return json({ok:true});
    }
    if(method==="POST"&&path[0]==="collections"&&path[2]==="close"){
      const visitId=path[1],{paymentMethod}=await body<{paymentMethod:"cash"|"transfer"}>(request);if(!["cash","transfer"].includes(paymentMethod))return json({error:"Metodo di pagamento non valido."},400);const visit=await db().prepare("SELECT * FROM collection_visits WHERE id=? AND status='open'").bind(visitId).first<Record<string,unknown>>();if(!visit)return json({error:"Incasso non aperto."},409);const rows=(await db().prepare("SELECT * FROM machine_collections WHERE visit_id=?").bind(visitId).all<Record<string,unknown>>()).results||[];if(!rows.length)return json({error:"Registra almeno una macchina prima di chiudere."},400);const sum=(k:string)=>rows.reduce((t,r)=>t+Number(r[k]||0),0),round=(v:number)=>Math.round((v+Number.EPSILON)*100)/100;const partialIn=round(sum("partial_in")),partialOut=round(sum("partial_out")),drawer=round(sum("drawer")),taxes=round(sum("taxes")),netDrawer=round(sum("net_drawer")),managerShare=round(sum("manager_share")),exerciseShare=round(sum("exercise_share")),serviceShare=round(sum("service_share")),deposits=Number(visit.deposits||0),collected=round((paymentMethod==="cash"?drawer-exerciseShare:drawer)-deposits);const totals={played:partialIn,paid:partialOut,drawer,taxes,netDrawer,managerShare,exerciseShare,serviceShare,deposits,collected,paymentMethod};const closedAt=now();await db().prepare("UPDATE collection_visits SET status='closed',payment_method=?,closed_at=?,totals_json=? WHERE id=?").bind(paymentMethod,closedAt,JSON.stringify(totals),visitId).run();return json({ok:true,closedAt,totals});
    }
    if(method==="POST"&&path[0]==="collections"&&path[2]==="cancel"){
      if(!requireAdmin(auth))return json({error:"Solo un amministratore può annullare un incasso."},403);const row=await db().prepare("SELECT local_key AS localKey,local FROM collection_visits WHERE id=? AND status IN ('open','closed')").bind(path[1]).first<{localKey:string;local:string}>();if(!row)return json({error:"Incasso non annullabile."},404);await db().prepare("UPDATE collection_visits SET status='cancelled',cancelled_at=?,cancelled_by=? WHERE id=?").bind(now(),auth.user.id,path[1]).run();await db().prepare("INSERT INTO alerts(id,kind,message,local_key,created_by,created_by_name,created_at) VALUES(?,?,?,?,?,?,?)").bind(crypto.randomUUID(),"collection_cancelled",`Incasso ${path[1]} annullato da ${auth.user.name} · ${row.local}.`,row.localKey,auth.user.id,auth.user.name,now()).run();return json({ok:true});
    }
    if(method==="POST"&&path.join("/")==="finance-settings"){
      if(!requireAdmin(auth))return json({error:"Solo un amministratore può cambiare le percentuali aziendali."},403);const v=await body<{preuPercent:number;aamsPercent:number;serviceEnabled:boolean;servicePercent:number;counterTolerance:number}> (request);if(![v.preuPercent,v.aamsPercent,v.servicePercent,v.counterTolerance].every(Number.isFinite)||v.preuPercent<0||v.preuPercent>100||v.aamsPercent<0||v.aamsPercent>100||v.servicePercent<0||v.servicePercent>100||v.counterTolerance<0)return json({error:"Valori percentuali o tolleranza non validi."},400);await db().batch([["preu_percent",v.preuPercent],["aams_percent",v.aamsPercent],["service_enabled",v.serviceEnabled?1:0],["service_percent",v.servicePercent],["counter_tolerance",v.counterTolerance]].map(([k,x])=>db().prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(k,String(x))));return json({ok:true});
    }
    if(method==="GET"&&path.join("/")==="alerts"){
      if(!requireAdmin(auth))return json({error:"Solo un amministratore può vedere gli allarmi."},403);const rows=await db().prepare("SELECT * FROM alerts WHERE resolved_at IS NULL ORDER BY created_at DESC LIMIT 500").all();return json({alerts:rows.results||[]});
    }
    if(method==="POST"&&path[0]==="alerts"&&path[2]==="resolve"){
      if(!requireAdmin(auth))return json({error:"Solo un amministratore può archiviare gli allarmi."},403);await db().prepare("UPDATE alerts SET resolved_at=? WHERE id=?").bind(now(),path[1]).run();return json({ok:true});
    }
    if(method==="GET"&&path.join("/")==="field-messages"){
      const rows=await db().prepare("SELECT * FROM field_messages ORDER BY created_at DESC LIMIT 200").all();return json({messages:rows.results||[]});
    }
    if(method==="POST"&&path.join("/")==="field-messages"){
      if(!requireAdmin(auth))return json({error:"Solo un amministratore può inviare messaggi agli esattori."},403);const {body:message}=await body<{body:string}>(request);if(!message?.trim())return json({error:"Scrivi un messaggio."},400);const item={id:crypto.randomUUID(),body:message.trim().slice(0,2000),createdByName:auth.user.name,createdAt:now()};await db().prepare("INSERT INTO field_messages(id,body,created_by,created_by_name,created_at) VALUES(?,?,?,?,?)").bind(item.id,item.body,auth.user.id,item.createdByName,item.createdAt).run();return json({message:item},201);
    }
    if(method==="POST"&&path.join("/")==="field-notes"){
      const input=await body<{kind:string;localKey:string;machineId?:string;body:string}>(request);if(!["changer","fault"].includes(input.kind)||!input.localKey||!input.body?.trim())return json({error:"Dati non validi."},400);const item={id:crypto.randomUUID(),kind:input.kind,localKey:input.localKey,machineId:input.machineId||"",body:input.body.trim().slice(0,1500),createdByName:auth.user.name,createdAt:now()};await db().prepare("INSERT INTO field_notes(id,kind,local_key,machine_id,body,created_by,created_by_name,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(item.id,item.kind,item.localKey,item.machineId,item.body,auth.user.id,item.createdByName,item.createdAt).run();return json({note:item},201);
    }
    if(method==="GET"&&path[0]==="field-notes"){
      const rows=await db().prepare("SELECT * FROM field_notes WHERE local_key=? ORDER BY created_at DESC LIMIT 200").bind(decodeURIComponent(path[1]||"")).all();return json({notes:rows.results||[]});
    }
    if(method==="GET"&&path.join("/")==="day-summary"){
      const date=businessDate();const [rows,closing]=await Promise.all([db().prepare("SELECT * FROM collection_visits WHERE business_day=? ORDER BY started_at DESC").bind(date).all<Record<string,unknown>>(),db().prepare("SELECT * FROM day_closings WHERE day=? AND status='closed' LIMIT 1").bind(date).first<Record<string,unknown>>()]);return json({visits:(rows.results||[]).map(r=>({...r,totals:JSON.parse(String(r.totals_json||"{}"))})),closing:closing?{...closing,totals:JSON.parse(String(closing.totals_json||"{}"))}:null});
    }
    if(method==="POST"&&path.join("/")==="day-close"){
      const date=businessDate();const opened=await db().prepare("SELECT COUNT(*) AS n FROM collection_visits WHERE business_day=? AND status='open'").bind(date).first<{n:number}>();if(Number(opened?.n||0)>0)return json({error:"Chiudi prima gli incassi ancora aperti."},409);const old=await db().prepare("SELECT id FROM day_closings WHERE day=? AND status='closed'").bind(date).first();if(old)return json({error:"La giornata è già stata chiusa."},409);const rows=(await db().prepare("SELECT totals_json FROM collection_visits WHERE business_day=? AND status='closed'").bind(date).all<{totals_json:string}>()).results||[];const totals=rows.map(r=>JSON.parse(r.totals_json||"{}"));const sum=(k:string)=>Math.round((totals.reduce((n,t)=>n+Number(t[k]||0),0)+Number.EPSILON)*100)/100;const summary={played:sum("played"),paid:sum("paid"),drawer:sum("drawer"),taxes:sum("taxes"),collected:sum("collected"),deposits:sum("deposits"),managerShare:sum("managerShare"),exerciseShare:sum("exerciseShare"),serviceShare:sum("serviceShare")};const id=crypto.randomUUID(),closedAt=now();await db().prepare("INSERT INTO day_closings(id,day,status,closed_at,closed_by,closed_by_name,totals_json) VALUES(?,?,'closed',?,?,?,?)").bind(id,date,closedAt,auth.user.id,auth.user.name,JSON.stringify(summary)).run();return json({ok:true,id,totals:summary,closedAt});
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
      const retePercent=Number(input.retePercent??1),exercisePercent=Number(input.exercisePercent??50);if(![retePercent,exercisePercent].every(v=>Number.isFinite(v)&&v>=0&&v<=100))return json({error:"Percentuali locale non valide."},400);
      await db().prepare(`INSERT INTO local_profiles(local_key,local_code,pdv_code,name,address,comune,provincia,ragione_sociale,insegna,partita_iva,codice_fiscale,contact_name,phone,email,pec,notes,rete_percent,exercise_percent,updated_at)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(local_key) DO UPDATE SET name=excluded.name,address=excluded.address,comune=excluded.comune,provincia=excluded.provincia,ragione_sociale=excluded.ragione_sociale,insegna=excluded.insegna,partita_iva=excluded.partita_iva,codice_fiscale=excluded.codice_fiscale,contact_name=excluded.contact_name,phone=excluded.phone,email=excluded.email,pec=excluded.pec,notes=excluded.notes,rete_percent=excluded.rete_percent,exercise_percent=excluded.exercise_percent,updated_at=excluded.updated_at`)
        .bind(decodeURIComponent(path[1]),current?.localCode||"",current?.pdvCode||"",values.name,values.address,values.comune,values.provincia,values.ragioneSociale,values.insegna,values.partitaIva,values.codiceFiscale,values.contactName,values.phone,values.email,values.pec,values.notes,retePercent,exercisePercent,now()).run();
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
      const { company,address="",vat="",fiscalCode="" } = await body<{ company: string;address?:string;vat?:string;fiscalCode?:string }>(request);
      if (!company?.trim() || company.length > 100) return json({ error: "Nome azienda non valido." }, 400);
      await db().prepare("INSERT INTO settings(key,value) VALUES('company',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(company.trim()).run();
      for(const [key,value] of [["company_address",address],["company_vat",vat],["company_cf",fiscalCode]] as const)await db().prepare("INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").bind(key,String(value).slice(0,200)).run();
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
