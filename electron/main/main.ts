/**
 * NETRA endpoint client — Electron main process.
 *
 * The client is the user-facing surface only. It holds no device key, collects
 * no telemetry and computes no risk: those belong to the Rust agent and the Go
 * control plane respectively (spec §5).
 */

import { app, BrowserWindow } from "electron";
import { hostname } from "node:os";
import path from "node:path";
import { registerIpcHandlers } from "./ipc";
import {
  applyContentSecurityPolicy,
  contentSecurityPolicy,
  denyAllPermissions,
  enforceSingleInstance,
  restrictNavigation,
} from "./security";

const BACKEND_URL = process.env.NETRA_BACKEND_URL ?? "http://localhost:8080";
const DEV_SERVER_URL = process.env.NETRA_DEV_SERVER_URL;

function createWindow(): BrowserWindow {
  const window = new BrowserWindow({
    width: 980,
    height: 720,
    minWidth: 820,
    minHeight: 600,
    title: "NETRA",
    backgroundColor: "#14181d",
    show: false,
    webPreferences: {
      // The three settings that matter most (spec §6).
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      webSecurity: true,
      preload: path.join(__dirname, "..", "preload", "preload.js"),
    },
  });

  window.once("ready-to-show", () => window.show());

  if (DEV_SERVER_URL) {
    void window.loadURL(DEV_SERVER_URL);
  } else {
    void window.loadFile(path.join(__dirname, "..", "..", "dist", "renderer", "index.html"));
  }

  restrictNavigation(window, DEV_SERVER_URL ?? "file://");
  return window;
}

if (!enforceSingleInstance()) {
  app.quit();
} else {
  void app.whenReady().then(() => {
    applyContentSecurityPolicy(contentSecurityPolicy(BACKEND_URL, DEV_SERVER_URL));
    denyAllPermissions();
    registerIpcHandlers({ backendUrl: BACKEND_URL, hostname: hostname() });

    createWindow();

    app.on("activate", () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createWindow();
      }
    });
  });

  app.on("window-all-closed", () => {
    if (process.platform !== "darwin") {
      app.quit();
    }
  });
}
