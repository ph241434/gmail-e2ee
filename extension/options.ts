import { setSessionBridge } from "../src/ui/sessionBridge";
import { chromeSessionBridge } from "./session";

// The key manager is the web app, with its unlocked identity shared through session
// storage. The bridge must be in place before the app module runs, hence the dynamic import.
setSessionBridge(chromeSessionBridge);
void import("../src/main");
