// Cross-window bridge for the few UI-only flows that hop between modules
// (Send to Repeater, Send to Comparer, etc.). Each window has its own
// zustand instance — when a "sendTo" lands in the main while Repeater is
// detached, the detached store needs to mirror the mutation so the target
// module sees the pending payload.
//
// Flow:
//   1. window-A mutates appStore → wraps invoke('appstore_broadcast', ...)
//      → Rust re-emits 'appstore:sync' to ALL windows
//   2. All windows (including window-A) listen for 'appstore:sync'
//   3. Listener applies the mutation locally — but only if the originating
//      window label differs (avoids self-echo loop).
//
// For v0.3.7 we sync just `sendTo` and `pendingDeleteUrl`, which cover the
// existing cross-module send flows. Other zustand state stays local per
// window (most modules pull live data from the Rust backend anyway).

import { emit, listen, type UnlistenFn } from '@tauri-apps/api/event';
import { getCurrentWindow } from '@tauri-apps/api/window';
import type { ModuleId } from '../types';

export type CrossWindowAction =
  | {
      kind: 'sendTo';
      tool: string;
      method: string;
      url: string;
      requestRaw: string;
      responseRaw?: string;
      target?: 'left' | 'right';
    }
  | { kind: 'deleteSitemapNode'; url: string }
  | { kind: 'setActiveModule'; moduleId: ModuleId };

interface Envelope {
  source: string;
  action: CrossWindowAction;
}

const EVENT = 'appstore:sync';

let myLabel: string | null = null;

async function getMyLabel(): Promise<string> {
  if (myLabel !== null) return myLabel;
  try { myLabel = getCurrentWindow().label; } catch { myLabel = 'unknown'; }
  return myLabel;
}

export async function broadcastAction(action: CrossWindowAction): Promise<void> {
  const source = await getMyLabel();
  const envelope: Envelope = { source, action };
  try { await emit(EVENT, envelope); } catch (e) { console.error('[crossWindow] emit failed', e); }
}

export async function subscribeAction(
  handler: (action: CrossWindowAction) => void
): Promise<UnlistenFn> {
  const me = await getMyLabel();
  return listen<Envelope>(EVENT, (e) => {
    if (e.payload.source === me) return; // ignore self-echo
    handler(e.payload.action);
  });
}
