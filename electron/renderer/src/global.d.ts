import type { NetraBridge } from "@shared/contract";

declare global {
  interface Window {
    /** The only capability the renderer has beyond the DOM. */
    readonly netra: NetraBridge;
  }
}

export {};
