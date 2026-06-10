import {
  FluentProvider,
  webLightTheme,
} from "@fluentui/react-components";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ConnectionGrid } from "./components/ConnectionGrid";
import { SessionPage } from "./pages/SessionPage";

function App() {
  return (
    <FluentProvider theme={webLightTheme}>
      <BrowserRouter basename="/portal">
        <Routes>
          <Route path="/" element={<ConnectionGrid />} />
          <Route path="/session/:id" element={<SessionPage />} />
        </Routes>
      </BrowserRouter>
    </FluentProvider>
  );
}

export default App;
