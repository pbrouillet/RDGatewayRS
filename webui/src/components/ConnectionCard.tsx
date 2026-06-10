import {
  Card,
  CardHeader,
  CardFooter,
  Body1,
  Caption1,
  Button,
  makeStyles,
  tokens,
} from "@fluentui/react-components";
import {
  DesktopRegular,
  ArrowDownloadRegular,
  EditRegular,
  DeleteRegular,
  ServerRegular,
  LaptopRegular,
  PlugConnectedRegular,
} from "@fluentui/react-icons";
import type { Connection } from "../types";
import { rdpDownloadUrl } from "../api";

const useStyles = makeStyles({
  card: {
    width: "220px",
    cursor: "pointer",
    transition: "box-shadow 0.2s",
    ":hover": {
      boxShadow: tokens.shadow8,
    },
  },
  iconContainer: {
    display: "flex",
    justifyContent: "center",
    padding: "24px 0 8px",
    fontSize: "48px",
    color: tokens.colorBrandForeground1,
  },
});

const iconMap: Record<string, React.ReactElement> = {
  Desktop: <DesktopRegular />,
  Server: <ServerRegular />,
  Laptop: <LaptopRegular />,
};

interface Props {
  connection: Connection;
  onEdit: (c: Connection) => void;
  onDelete: (c: Connection) => void;
}

export function ConnectionCard({ connection, onEdit, onDelete }: Props) {
  const styles = useStyles();

  const handleDownload = () => {
    window.location.href = rdpDownloadUrl(connection.id);
  };

  const handleConnectWeb = (e: React.MouseEvent) => {
    e.stopPropagation();
    window.open(`/portal/session/${connection.id}`, "_blank");
  };

  return (
    <Card className={styles.card} onClick={handleDownload}>
      <div className={styles.iconContainer}>
        {iconMap[connection.icon] ?? <DesktopRegular />}
      </div>
      <CardHeader
        header={<Body1><b>{connection.name}</b></Body1>}
        description={
          <Caption1>
            {connection.host}:{connection.port}
          </Caption1>
        }
      />
      {connection.description && (
        <Caption1 style={{ padding: "0 12px 8px" }}>
          {connection.description}
        </Caption1>
      )}
      <CardFooter>
        <Button
          icon={<PlugConnectedRegular />}
          size="small"
          appearance="primary"
          onClick={handleConnectWeb}
        >
          Web
        </Button>
        <Button
          icon={<ArrowDownloadRegular />}
          size="small"
          appearance="subtle"
          onClick={(e) => {
            e.stopPropagation();
            handleDownload();
          }}
        >
          RDP
        </Button>
        <Button
          icon={<EditRegular />}
          size="small"
          appearance="subtle"
          onClick={(e) => {
            e.stopPropagation();
            onEdit(connection);
          }}
        />
        <Button
          icon={<DeleteRegular />}
          size="small"
          appearance="subtle"
          onClick={(e) => {
            e.stopPropagation();
            onDelete(connection);
          }}
        />
      </CardFooter>
    </Card>
  );
}
