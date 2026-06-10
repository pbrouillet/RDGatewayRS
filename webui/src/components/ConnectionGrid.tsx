import { makeStyles, Title1, Spinner, MessageBar } from "@fluentui/react-components";
import { useState, useEffect, useCallback } from "react";
import type { Connection, ConnectionInput } from "../types";
import { listConnections, createConnection, updateConnection, deleteConnection } from "../api";
import { ConnectionCard } from "./ConnectionCard";
import { ConnectionForm } from "./ConnectionForm";

const useStyles = makeStyles({
  container: {
    padding: "24px",
    maxWidth: "1200px",
    margin: "0 auto",
  },
  header: {
    display: "flex",
    justifyContent: "space-between",
    alignItems: "center",
    marginBottom: "24px",
  },
  grid: {
    display: "flex",
    flexWrap: "wrap",
    gap: "16px",
  },
  center: {
    display: "flex",
    justifyContent: "center",
    padding: "48px",
  },
});

export function ConnectionGrid() {
  const styles = useStyles();
  const [connections, setConnections] = useState<Connection[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<Connection | null>(null);

  const refresh = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const data = await listConnections();
      setConnections(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load connections");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleCreate = async (input: ConnectionInput) => {
    try {
      await createConnection(input);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to create connection");
    }
  };

  const handleUpdate = async (input: ConnectionInput) => {
    if (!editing) return;
    try {
      await updateConnection(editing.id, input);
      setEditing(null);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to update connection");
    }
  };

  const handleDelete = async (conn: Connection) => {
    if (!confirm(`Delete connection "${conn.name}"?`)) return;
    try {
      await deleteConnection(conn.id);
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete connection");
    }
  };

  const handleEdit = (conn: Connection) => {
    setEditing(conn);
    setFormOpen(true);
  };

  const handleFormOpenChange = (open: boolean) => {
    setFormOpen(open);
    if (!open) setEditing(null);
  };

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <Title1>Connections</Title1>
        <ConnectionForm
          connection={editing}
          open={formOpen}
          onOpenChange={handleFormOpenChange}
          onSubmit={editing ? handleUpdate : handleCreate}
        />
      </div>
      {error && (
        <MessageBar intent="error" style={{ marginBottom: "16px" }}>
          {error}
        </MessageBar>
      )}
      {loading ? (
        <div className={styles.center}>
          <Spinner label="Loading connections..." />
        </div>
      ) : (
        <div className={styles.grid}>
          {connections.map((conn) => (
            <ConnectionCard
              key={conn.id}
              connection={conn}
              onEdit={handleEdit}
              onDelete={handleDelete}
            />
          ))}
          {connections.length === 0 && !loading && (
            <div className={styles.center} style={{ width: "100%" }}>
              No connections yet. Click "Add Connection" to get started.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
