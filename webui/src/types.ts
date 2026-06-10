export interface Connection {
  id: number;
  name: string;
  host: string;
  port: number;
  description: string | null;
  icon: string;
  created_at: string;
  updated_at: string;
}

export interface ConnectionInput {
  name: string;
  host: string;
  port: number;
  description: string | null;
  icon: string;
}
