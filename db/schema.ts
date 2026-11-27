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

export const machines = sqliteTable("machines", {
  id: text("id").primaryKey(),
  local: text("local").notNull().default(""),
  comune: text("comune").notNull().default(""),
  address: text("address").notNull().default(""),
  model: text("model").notNull().default(""),
  codeModel: text("code_model").notNull().default(""),
  codeProvv: text("code_provv").notNull().default(""),
  status: text("status").notNull().default(""),
  cntIn: text("cnt_in").notNull().default(""),
  cntOut: text("cnt_out").notNull().default(""),
  exerciseCode: text("exercise_code").notNull().default(""),
  raw: text("raw_json").notNull().default("{}"),
});

export const settings = sqliteTable("settings", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
});
