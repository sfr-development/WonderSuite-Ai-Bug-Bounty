// Thin helper around tauri-plugin-notification. Honors the per-user toggle
// stored in localStorage `ws_desktop_notifications_enabled`. First call lazily
// requests OS permission; subsequent calls just fire. Failures are silent —
// missing OS permission shouldn't break the app.

import {
  isPermissionGranted,
  requestPermission,
  sendNotification,
} from '@tauri-apps/plugin-notification';

const STORAGE_KEY = 'ws_desktop_notifications_enabled';

export function notificationsEnabled(): boolean {
  return localStorage.getItem(STORAGE_KEY) !== '0';
}

export function setNotificationsEnabled(on: boolean): void {
  localStorage.setItem(STORAGE_KEY, on ? '1' : '0');
}

let permissionPromise: Promise<boolean> | null = null;

async function ensurePermission(): Promise<boolean> {
  if (permissionPromise) return permissionPromise;
  permissionPromise = (async () => {
    try {
      let granted = await isPermissionGranted();
      if (!granted) {
        const reply = await requestPermission();
        granted = reply === 'granted';
      }
      return granted;
    } catch {
      return false;
    }
  })();
  return permissionPromise;
}

export interface DesktopNotice {
  title: string;
  body?: string;
  /** OS-side identifier so a later notify with the same id can replace it (Windows toast). */
  group?: string;
}

export async function desktopNotify(n: DesktopNotice): Promise<void> {
  if (!notificationsEnabled()) return;
  try {
    const ok = await ensurePermission();
    if (!ok) return;
    sendNotification({ title: n.title, body: n.body });
  } catch (e) {
    // Don't surface — plugin not available in dev, etc.
    console.warn('[desktopNotify]', e);
  }
}
