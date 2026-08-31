/**
 * Preload bridge.
 *
 * This is the only code that runs with access to both Node and the renderer.
 * It exposes a fixed set of named functions and nothing else: no module
 * objects, no ipcRenderer, and no channel name accepted from the page. A
 * renderer compromised by XSS gains these calls, not IPC.
 *
 * Only `signIn` takes an argument, and the main process validates it rather
 * than trusting the renderer.
 */

import { contextBridge, ipcRenderer } from "electron";
import { CHANNELS, type NetraBridge } from "../shared/contract";

const bridge: NetraBridge = {
  getDeviceStatus: () => ipcRenderer.invoke(CHANNELS.deviceStatus),
  getRisk: () => ipcRenderer.invoke(CHANNELS.risk),
  getPolicy: () => ipcRenderer.invoke(CHANNELS.policy),
  getConnectionStatus: () => ipcRenderer.invoke(CHANNELS.connection),
  getSession: () => ipcRenderer.invoke(CHANNELS.session),
  // The subject is validated in the main process; the renderer is not trusted
  // to send a well-formed value.
  signIn: (subject: string) => ipcRenderer.invoke(CHANNELS.signIn, subject),
  signOut: () => ipcRenderer.invoke(CHANNELS.signOut),
};

contextBridge.exposeInMainWorld("netra", bridge);
