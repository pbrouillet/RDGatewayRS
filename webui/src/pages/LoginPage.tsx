import { useState } from "react";
import {
  Card,
  CardHeader,
  Input,
  Button,
  Label,
  Title1,
  MessageBar,
  MessageBarBody,
  Tab,
  TabList,
  makeStyles,
  tokens,
} from "@fluentui/react-components";
import { useAuth } from "../contexts/AuthContext";

const useStyles = makeStyles({
  container: {
    display: "flex",
    justifyContent: "center",
    alignItems: "center",
    minHeight: "100vh",
    backgroundColor: tokens.colorNeutralBackground2,
  },
  card: {
    width: "400px",
    padding: "24px",
  },
  form: {
    display: "flex",
    flexDirection: "column",
    gap: "16px",
    marginTop: "16px",
  },
  field: {
    display: "flex",
    flexDirection: "column",
    gap: "4px",
  },
});

export function LoginPage() {
  const styles = useStyles();
  const { login, register } = useAuth();
  const [tab, setTab] = useState<"signin" | "signup">("signin");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (tab === "signin") {
        await login(username, password);
      } else {
        await register(username, password);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className={styles.container}>
      <Card className={styles.card}>
        <CardHeader header={<Title1>RD Gateway</Title1>} />
        <TabList
          selectedValue={tab}
          onTabSelect={(_, data) => setTab(data.value as "signin" | "signup")}
        >
          <Tab value="signin">Sign In</Tab>
          <Tab value="signup">Sign Up</Tab>
        </TabList>
        <form className={styles.form} onSubmit={handleSubmit}>
          {error && (
            <MessageBar intent="error">
              <MessageBarBody>{error}</MessageBarBody>
            </MessageBar>
          )}
          <div className={styles.field}>
            <Label htmlFor="username">Username</Label>
            <Input
              id="username"
              value={username}
              onChange={(_, data) => setUsername(data.value)}
              required
              autoFocus
            />
          </div>
          <div className={styles.field}>
            <Label htmlFor="password">Password</Label>
            <Input
              id="password"
              type="password"
              value={password}
              onChange={(_, data) => setPassword(data.value)}
              required
            />
          </div>
          <Button appearance="primary" type="submit" disabled={loading}>
            {loading ? "..." : tab === "signin" ? "Sign In" : "Sign Up"}
          </Button>
        </form>
      </Card>
    </div>
  );
}
