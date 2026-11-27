import { integer, real, sqliteTable, text } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  username: text("username").notNull().unique(),
  name: text("name").notNull(),
  passwordSalt: text("password_salt").notNull(),
  passwordHash: text("password_hash").notNull(),
  role: text("role").notNull().default("collector"),
  active: integer("active").notNull().default(1),
  createdAt: text("created_at").notNull(),
});

export const sessions = sqliteTable("sessions", {
  tokenHash: text("token_hash").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id),
  deviceId: text("device_id"),
  expiresAt: text("expires_at").notNull(),
  createdAt: text("created_at").notNull(),
});

export const devices = sqliteTable("devices", {
  id: text("id").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id),
  label: text("label").notNull(),
  createdAt: text("created_at").notNull(),
  lastSeenAt: text("last_seen_at").notNull(),
  revoked: integer("revoked").notNull().default(0),
});

export const pairCodes = sqliteTable("pair_codes", {
  codeHash: text("code_hash").primaryKey(),
  userId: text("user_id").notNull().references(() => users.id),
  createdBy: text("created_by").notNull(),
  expiresAt: text("expires_at").notNull(),
  usedAt: text("used_at"),
});

export const authAttempts = sqliteTable("auth_attempts", {
  id: integer("id").primaryKey({ autoIncrement: true }),
  addressHash: text("address_hash").notNull(),
  createdAt: text("created_at").notNull(),
});

export const deposits = sqliteTable("deposits", {
  id: text("id").primaryKey(),
  local: text("local").notNull(),
  amount: real("amount").notNull(),
  occurredAt: text("occurred_at").notNull(),
  collector: text("collector").notNull(),
  note: text("note").notNull().default(""),
  createdBy: text("created_by").notNull().references(() => users.id),
});

export const importBatches = sqliteTable("import_batches", {
  id: text("id").primaryKey(),
  fingerprint: text("fingerprint").notNull().unique(),
  importedAt: text("imported_at").notNull(),
  importedBy: text("imported_by").notNull().references(() => users.id),
  rowCount: integer("row_count").notNull(),
  localCount: integer("local_count").notNull(),
});

export const machineHistory = sqliteTable("machine_history", {
  id: text("id").primaryKey(),
  machineId: text("machine_id").notNull(),
  importId: text("import_id").notNull().references(() => importBatches.id),
  localKey: text("local_key").notNull(),
  local: text("local").notNull(),
  localCode: text("local_code").notNull().default(""),
  comune: text("comune").notNull().default(""),
  address: text("address").notNull().default(""),
  model: text("model").notNull().default(""),
  codeModel: text("code_model").notNull().default(""),
  codeProvv: text("code_provv").notNull().default(""),
  status: text("status").notNull().default(""),
  cntIn: text("cnt_in").notNull().default(""),
  cntOut: text("cnt_out").notNull().default(""),
  exerciseCode: text("exercise_code").notNull().default(""),
  pdaMac: text("pda_mac").notNull().default(""),
  readAt: text("read_at").notNull(),
  raw: text("raw_json").notNull().default("{}"),
});

export const localProfiles = sqliteTable("local_profiles", {
  localKey: text("local_key").primaryKey(),
  localCode: text("local_code").notNull().default(""),
  pdvCode: text("pdv_code").notNull().default(""),
  name: text("name").notNull(),
  address: text("address").notNull().default(""),
  comune: text("comune").notNull().default(""),
  provincia: text("provincia").notNull().default(""),
  ragioneSociale: text("ragione_sociale").notNull().default(""),
  insegna: text("insegna").notNull().default(""),
  partitaIva: text("partita_iva").notNull().default(""),
  codiceFiscale: text("codice_fiscale").notNull().default(""),
  contactName: text("contact_name").notNull().default(""),
  phone: text("phone").notNull().default(""),
  email: text("email").notNull().default(""),
  pec: text("pec").notNull().default(""),
  notes: text("notes").notNull().default(""),
  updatedAt: text("updated_at").notNull(),
});

export const machines = sqliteTable("machines", {
  id: text("id").primaryKey(),
  localKey: text("local_key").notNull().default(""),
  local: text("local").notNull().default(""),
  localCode: text("local_code").notNull().default(""),
  comune: text("comune").notNull().default(""),
  address: text("address").notNull().default(""),
  provincia: text("provincia").notNull().default(""),
  pdvCode: text("pdv_code").notNull().default(""),
  pdaMac: text("pda_mac").notNull().default(""),
  model: text("model").notNull().default(""),
  codeModel: text("code_model").notNull().default(""),
  codeProvv: text("code_provv").notNull().default(""),
  status: text("status").notNull().default(""),
  cntIn: text("cnt_in").notNull().default(""),
  cntOut: text("cnt_out").notNull().default(""),
  exerciseCode: text("exercise_code").notNull().default(""),
  hopper1: real("hopper1").notNull().default(0),
  hopper2: real("hopper2").notNull().default(0),
  lastImportId: text("last_import_id").notNull().default(""),
  raw: text("raw_json").notNull().default("{}"),
});

export const settings = sqliteTable("settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
});
