/**
 * Preload bridge.
 *
 * This is the only code that runs with access to both Node and the renderer.
 * It exposes four zero-argument functions and nothing else: no module objects,
 * no ipcRenderer, no channel name accepted from the page. A renderer
 * compromised by XSS therefore gains four read-only queries, not IPC.
 */

import { contextBridge, ipcRenderer } from "electron";
import { CHANNELS, type NetraBridge } from "../shared/contract";

const bridge: NetraBridge = {
  getDeviceStatus: () => ipcRenderer.invoke(CHANNELS.deviceStatus),
  getRisk: () => ipcRenderer.invoke(CHANNELS.risk),
  getPolicy: () => ipcRenderer.invoke(CHANNELS.policy),
  getConnectionStatus: () => ipcRenderer.invoke(CHANNELS.connection),
};

contextBridge.exposeInMainWorld("netra", bridge);
