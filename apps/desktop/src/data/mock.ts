// Sample data for the UI while the backend is stubbed. All values are fake.

export type SecretKind = "password" | "api_key" | "access_token" | "env_var" | "ssh_key" | "certificate";

export const kindLabels: Record<SecretKind, string> = {
  api_key: "API key",
  access_token: "Access token",
  password: "Password",
  env_var: "Environment variable",
  ssh_key: "SSH key",
  certificate: "Certificate",
};

export interface Environment {
  id: string;
  name: string;
}

export interface Project {
  id: string;
  name: string;
  environments: Environment[];
}

export interface Secret {
  id: string;
  projectId?: string;
  environmentId?: string | null;
  name: string;
  kind: SecretKind;
  value: string;
  note?: string;
  updatedAt?: number;
  project_id?: string;
  environment_id?: string | null;
  item_id?: string;
  updated_at?: number;
  value_tail?: string;
}

const envs = (): Environment[] => [
  { id: "development", name: "Development" },
  { id: "staging", name: "Staging" },
  { id: "production", name: "Production" },
];

export const projects: Project[] = [
  { id: "payments-api", name: "payments-api", environments: envs() },
  { id: "web-dashboard", name: "web-dashboard", environments: envs() },
  { id: "mobile-app", name: "mobile-app", environments: envs().slice(0, 2) },
];

const now = Date.now();
const h = 3_600_000;
let n = 0;
const s = (projectId: string, environmentId: string, name: string, kind: SecretKind, value: string, agoHours: number, note?: string): Secret => ({
  id: `s${++n}`,
  projectId,
  environmentId,
  name,
  kind,
  value,
  note,
  updatedAt: now - agoHours * h,
});

export const initialSecrets: Secret[] = [
  s("payments-api", "production", "STRIPE_SECRET_KEY", "api_key", "sk_test_EXAMPLE0000000000004f2a", 2),
  s("payments-api", "production", "DATABASE_URL", "env_var", "postgres://payments:example@db.internal:5432/payments", 26),
  s("payments-api", "production", "JWT_SIGNING_KEY", "access_token", "example-signing-key-7d1c9b", 72),
  s("payments-api", "production", "WEBHOOK_SECRET", "api_key", "whsec_EXAMPLE00000000c81e", 140),
  s("payments-api", "production", "deploy@payments", "ssh_key", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEKEYONLY deploy", 400, "CI deploy key"),
  s("payments-api", "staging", "STRIPE_SECRET_KEY", "api_key", "sk_test_EXAMPLE0000000000009b31", 5),
  s("payments-api", "staging", "DATABASE_URL", "env_var", "postgres://payments:example@staging-db:5432/payments", 50),
  s("payments-api", "staging", "ADMIN_PASSWORD", "password", "correct-horse-example", 300),
  s("payments-api", "development", "DATABASE_URL", "env_var", "postgres://localhost:5432/payments_dev", 1),
  s("payments-api", "development", "STRIPE_SECRET_KEY", "api_key", "sk_test_EXAMPLE00000000000011aa", 9),
  s("payments-api", "development", "LOCAL_TLS_CERT", "certificate", "-----BEGIN CERTIFICATE-----\nEXAMPLE\n-----END CERTIFICATE-----", 900),
  s("payments-api", "development", "SENTRY_DSN", "env_var", "https://example@o0.ingest.example.io/0", 30),
  s("web-dashboard", "production", "NEXT_PUBLIC_API_URL", "env_var", "https://api.example.com", 12),
  s("web-dashboard", "production", "SESSION_SECRET", "access_token", "example-session-secret-55ab", 200),
  s("web-dashboard", "development", "NEXT_PUBLIC_API_URL", "env_var", "http://localhost:4000", 3),
  s("mobile-app", "development", "MAPS_API_KEY", "api_key", "EXAMPLE-maps-key-0001", 48),
];

export type Plan = "free" | "pro";

export const thisDevice = { name: "Desktop" };

export interface Device {
  id: string;
  name: string;
  platform: string;
  /** Short fingerprint of the device public key. */
  fingerprint: string;
  addedAt: number;
  lastSyncAt?: number;
  revokedAt?: number;
  current?: boolean;
}

export const initialDevices: Device[] = [
  { id: "d1", name: "Desktop", platform: "macOS", fingerprint: "7F3A 18E0 91C2", addedAt: now - 21 * 24 * h, current: true },
];

/** Device that "scans" the pairing code in the mock flow. */
export const mockNewDevice = { name: "iPhone 16", platform: "iOS", fingerprint: "91DD 3C07 5AB4" };
