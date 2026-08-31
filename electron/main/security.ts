/**
 * Electron hardening (spec §6, §38).
 *
 * These are applied process-wide rather than per-window so that a window
 * created later cannot accidentally opt out of them.
 */

import { app, shell, session, type BrowserWindow } from "electron";

/**
 * Content Security Policy for the renderer.
 *
 * `connect-src` is limited to the local backend: the client must not be able
 * to exfiltrate to an arbitrary origin if the renderer is ever compromised.
 */
export function contentSecurityPolicy(backendUrl: string, devServer?: string): string {
  const connect = ["'self'", backendUrl, devServer].filter(Boolean).join(" ");
  const scriptSrc = devServer ? `'self' ${devServer}` : "'self'";
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    // Vite injects styles inline; scripts are never allowed to be inline.
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src ${connect}`,
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
}

/** Applies the CSP to every response served to the renderer. */
export function applyContentSecurityPolicy(policy: string): void {
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        "Content-Security-Policy": [policy],
      },
    });
  });
}

/**
 * Denies every permission request.
 *
 * NETRA is explicitly not a surveillance tool (spec §34): the client has no
 * legitimate need for camera, microphone, screen capture or geolocation, so
 * the safest configuration is a blanket denial rather than a filter that could
 * be widened by a later change.
 */
export function denyAllPermissions(): void {
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => {
    callback(false);
  });
  session.defaultSession.setPermissionCheckHandler(() => false);
}

/**
 * Blocks in-app navigation to foreign origins and routes external links to the
 * system browser, so a redirect can never turn the client into a browser for
 * attacker-controlled content.
 */
export function restrictNavigation(window: BrowserWindow, allowedOrigin: string): void {
  window.webContents.on("will-navigate", (event, url) => {
    if (!url.startsWith(allowedOrigin)) {
      event.preventDefault();
    }
  });

  window.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith("https://")) {
      void shell.openExternal(url);
    }
    return { action: "deny" };
  });
}

/** Prevents a second instance from racing the first over local state. */
export function enforceSingleInstance(): boolean {
  return app.requestSingleInstanceLock();
}
