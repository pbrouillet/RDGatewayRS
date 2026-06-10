import type { Connection, ConnectionInput } from "./types";

const API_BASE = "/api/connections";

export async function listConnections(): Promise<Connection[]> {
  const res = await fetch(API_BASE);
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
  if (!res.ok) throw new Error(`Failed to update connection: ${res.statusText}`);
}

export async function deleteConnection(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Failed to delete connection: ${res.statusText}`);
}

export function rdpDownloadUrl(id: number): string {
  return `${API_BASE}/${id}/rdp`;
}

export async function createSessionToken(
  id: number
): Promise<{ token: string; expires_in: number }> {
  const res = await fetch(`${API_BASE}/${id}/session`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to create session: ${res.statusText}`);
  return res.json();
}
