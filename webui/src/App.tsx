import {
  FluentProvider,
  webLightTheme,
} from "@fluentui/react-components";
import { ConnectionGrid } from "./components/ConnectionGrid";

function App() {
  return (
    <FluentProvider theme={webLightTheme}>
      <ConnectionGrid />
    </FluentProvider>
  );
}

export default App;
