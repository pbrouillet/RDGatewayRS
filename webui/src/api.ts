import type { Connection, ConnectionInput } from "./types";

const API_BASE = "/api/connections";

export async function listConnections(): Promise<Connection[]> {
  const res = await fetch(API_BASE);
  if (res.status === 401) throw new AuthError();
  if (!res.ok) throw new Error(`Failed to list connections: ${res.statusText}`);
  return res.json();
}

export async function createConnection(
  input: ConnectionInput
): Promise<Connection> {
  const res = await fetch(API_BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (res.status === 401) throw new AuthError();
  if (!res.ok) throw new Error(`Failed to create connection: ${res.statusText}`);
  return res.json();
}

export async function updateConnection(
  id: number,
  input: ConnectionInput
): Promise<void> {
  const res = await fetch(`${API_BASE}/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(input),
  });
  if (res.status === 401) throw new AuthError();
  if (!res.ok) throw new Error(`Failed to update connection: ${res.statusText}`);
}

export async function deleteConnection(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/${id}`, { method: "DELETE" });
  if (res.status === 401) throw new AuthError();
  if (!res.ok) throw new Error(`Failed to delete connection: ${res.statusText}`);
}

export function rdpDownloadUrl(id: number): string {
  return `${API_BASE}/${id}/rdp`;
}

export async function createSessionToken(
  id: number
): Promise<{ token: string; expires_in: number }> {
  const res = await fetch(`${API_BASE}/${id}/session`, { method: "POST" });
  if (res.status === 401) throw new AuthError();
  if (!res.ok) throw new Error(`Failed to create session: ${res.statusText}`);
  return res.json();
}

// --- Auth API ---

export interface AuthUser {
  id: number;
  username: string;
}

export class AuthError extends Error {
  constructor() {
    super("Authentication required");
    this.name = "AuthError";
  }
}

export async function signup(username: string, password: string): Promise<AuthUser> {
  const res = await fetch("/api/auth/signup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Signup failed: ${res.statusText}`);
  }
  return res.json();
}

export async function signin(username: string, password: string): Promise<AuthUser> {
  const res = await fetch("/api/auth/signin", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `Sign in failed: ${res.statusText}`);
  }
  return res.json();
}

export async function signout(): Promise<void> {
  await fetch("/api/auth/signout", { method: "POST" });
}

export async function getMe(): Promise<AuthUser | null> {
  const res = await fetch("/api/auth/me");
  if (res.status === 401) return null;
  if (!res.ok) return null;
  return res.json();
}
