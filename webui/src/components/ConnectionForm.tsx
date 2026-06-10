import {
  Dialog,
  DialogTrigger,
  DialogSurface,
  DialogTitle,
  DialogBody,
  DialogActions,
  DialogContent,
  Button,
  Input,
  Label,
  Dropdown,
  Option,
  Textarea,
  makeStyles,
} from "@fluentui/react-components";
import { AddRegular } from "@fluentui/react-icons";
import { useState, useEffect } from "react";
import type { Connection, ConnectionInput } from "../types";

const useStyles = makeStyles({
  field: {
    display: "flex",
    flexDirection: "column",
    gap: "4px",
    marginBottom: "12px",
  },
  row: {
    display: "flex",
    gap: "12px",
  },
});

const ICON_OPTIONS = ["Desktop", "Server", "Laptop"];

interface Props {
  connection?: Connection | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onSubmit: (input: ConnectionInput) => void;
}

export function ConnectionForm({
  connection,
  open,
  onOpenChange,
  onSubmit,
}: Props) {
  const styles = useStyles();
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(3389);
  const [description, setDescription] = useState("");
  const [icon, setIcon] = useState("Desktop");

  useEffect(() => {
    if (connection) {
      setName(connection.name);
      setHost(connection.host);
      setPort(connection.port);
      setDescription(connection.description ?? "");
      setIcon(connection.icon);
    } else {
      setName("");
      setHost("");
      setPort(3389);
      setDescription("");
      setIcon("Desktop");
    }
  }, [connection, open]);

  const handleSubmit = () => {
    onSubmit({
      name,
      host,
      port,
      description: description || null,
      icon,
    });
    onOpenChange(false);
  };

  const isValid = name.trim() !== "" && host.trim() !== "" && port > 0;

  return (
    <Dialog open={open} onOpenChange={(_e, data) => onOpenChange(data.open)}>
      <DialogTrigger disableButtonEnhancement>
        <Button icon={<AddRegular />} appearance="primary">
          Add Connection
        </Button>
      </DialogTrigger>
      <DialogSurface>
        <DialogBody>
          <DialogTitle>
            {connection ? "Edit Connection" : "New Connection"}
          </DialogTitle>
          <DialogContent>
            <div className={styles.field}>
              <Label htmlFor="conn-name" required>
                Name
              </Label>
              <Input
                id="conn-name"
                value={name}
                onChange={(_e, d) => setName(d.value)}
                placeholder="My Server"
              />
            </div>
            <div className={styles.row}>
              <div className={styles.field} style={{ flex: 1 }}>
                <Label htmlFor="conn-host" required>
                  Host
                </Label>
                <Input
                  id="conn-host"
                  value={host}
                  onChange={(_e, d) => setHost(d.value)}
                  placeholder="192.168.1.100"
                />
              </div>
              <div className={styles.field} style={{ width: "100px" }}>
                <Label htmlFor="conn-port" required>
                  Port
                </Label>
                <Input
                  id="conn-port"
                  type="number"
                  value={String(port)}
                  onChange={(_e, d) => setPort(Number(d.value) || 3389)}
                />
              </div>
            </div>
            <div className={styles.field}>
              <Label htmlFor="conn-icon">Icon</Label>
              <Dropdown
                id="conn-icon"
                value={icon}
                selectedOptions={[icon]}
                onOptionSelect={(_e, d) => setIcon(d.optionValue ?? "Desktop")}
              >
                {ICON_OPTIONS.map((opt) => (
                  <Option key={opt} value={opt}>
                    {opt}
                  </Option>
                ))}
              </Dropdown>
            </div>
            <div className={styles.field}>
              <Label htmlFor="conn-desc">Description</Label>
              <Textarea
                id="conn-desc"
                value={description}
                onChange={(_e, d) => setDescription(d.value)}
                placeholder="Optional description"
                rows={2}
              />
            </div>
          </DialogContent>
          <DialogActions>
            <DialogTrigger disableButtonEnhancement>
              <Button appearance="secondary">Cancel</Button>
            </DialogTrigger>
            <Button
              appearance="primary"
              onClick={handleSubmit}
              disabled={!isValid}
            >
              {connection ? "Save" : "Create"}
            </Button>
          </DialogActions>
        </DialogBody>
      </DialogSurface>
    </Dialog>
  );
}
