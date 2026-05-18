// v0.3.16: tiny helper so modules don't have to import useAppStore + remember
// the toast shape every time. `notifyError("Proxy", err)` lifts a thrown error
// to a user-visible toast instead of disappearing into console.error.
import { useAppStore } from '../stores';

function stringifyErr(err: unknown): string {
  if (err == null) return 'Unknown error';
  if (typeof err === 'string') return err;
  if (err instanceof Error) return err.message;
  try { return JSON.stringify(err); } catch { return String(err); }
}

export function notifyError(title: string, err: unknown): void {
  // Keep the console trace too — useful when triaging a bug report.
  console.error(`[${title}]`, err);
  useAppStore.getState().addToast({
    type: 'error',
    title,
    message: stringifyErr(err),
  });
}

export function notifySuccess(title: string, message?: string): void {
  useAppStore.getState().addToast({ type: 'success', title, message });
}

export function notifyWarning(title: string, message?: string): void {
  useAppStore.getState().addToast({ type: 'warning', title, message });
}

export function notifyInfo(title: string, message?: string): void {
  useAppStore.getState().addToast({ type: 'info', title, message });
}
