declare namespace Cloudflare {
  interface Env {
    DB?: D1Database;
    BUCKET?: R2Bucket;
  WG_SESSION_SECRET?: string;
  WG_BOOTSTRAP_KEY?: string;
  }
}
