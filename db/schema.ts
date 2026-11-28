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
  retePercent: real("rete_percent").notNull().default(1),
  exercisePercent: real("exercise_percent").notNull().default(50),
  updatedAt: text("updated_at").notNull(),
});

export const collectionVisits = sqliteTable("collection_visits", {
  id: text("id").primaryKey(),
  localKey: text("local_key").notNull(),
  local: text("local").notNull(),
  status: text("status").notNull().default("open"),
  paymentMethod: text("payment_method").notNull().default("cash"),
  businessDay: text("business_day").notNull(),
  startedAt: text("started_at").notNull(),
  closedAt: text("closed_at"),
  collectorId: text("collector_id").notNull().references(() => users.id),
  collectorName: text("collector_name").notNull(),
  deposits: real("deposits").notNull().default(0),
  totalsJson: text("totals_json").notNull().default("{}"),
  cancelledAt: text("cancelled_at"),
  cancelledBy: text("cancelled_by"),
});

export const machineCollections = sqliteTable("machine_collections", {
  id: text("id").primaryKey(),
  visitId: text("visit_id").notNull().references(() => collectionVisits.id),
  machineId: text("machine_id").notNull(),
  model: text("model").notNull().default(""),
  partialIn: real("partial_in").notNull(),
  partialOut: real("partial_out").notNull(),
  globalIn: real("global_in").notNull(),
  globalOut: real("global_out").notNull(),
  manualCounters: integer("manual_counters").notNull().default(0),
  drawer: real("drawer").notNull(),
  taxes: real("taxes").notNull(),
  netDrawer: real("net_drawer").notNull(),
  managerShare: real("manager_share").notNull(),
  exerciseShare: real("exercise_share").notNull(),
  serviceShare: real("service_share").notNull().default(0),
  createdAt: text("created_at").notNull(),
});

export const alerts = sqliteTable("alerts", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  message: text("message").notNull(),
  localKey: text("local_key").notNull().default(""),
  machineId: text("machine_id").notNull().default(""),
  createdBy: text("created_by").notNull().references(() => users.id),
  createdByName: text("created_by_name").notNull(),
  createdAt: text("created_at").notNull(),
  resolvedAt: text("resolved_at"),
});

export const fieldNotes = sqliteTable("field_notes", {
  id: text("id").primaryKey(),
  kind: text("kind").notNull(),
  localKey: text("local_key").notNull(),
  machineId: text("machine_id").notNull().default(""),
  body: text("body").notNull(),
  createdBy: text("created_by").notNull().references(() => users.id),
  createdByName: text("created_by_name").notNull(),
  createdAt: text("created_at").notNull(),
  resolvedAt: text("resolved_at"),
});

export const fieldMessages = sqliteTable("field_messages", {
  id: text("id").primaryKey(),
  body: text("body").notNull(),
  createdBy: text("created_by").notNull().references(() => users.id),
  createdByName: text("created_by_name").notNull(),
  createdAt: text("created_at").notNull(),
});

export const dayClosings = sqliteTable("day_closings", {
  id: text("id").primaryKey(),
  day: text("day").notNull(),
  status: text("status").notNull().default("closed"),
  closedAt: text("closed_at").notNull(),
  closedBy: text("closed_by").notNull().references(() => users.id),
  closedByName: text("closed_by_name").notNull(),
  totalsJson: text("totals_json").notNull().default("{}"),
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
