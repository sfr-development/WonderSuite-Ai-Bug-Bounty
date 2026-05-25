import { useEffect } from 'react';
import { useAppStore } from '../stores';
import type { ModuleId } from '../types';

const MODULE_KEYS: Record<string, ModuleId> = {
  '1': 'dashboard',
  '2': 'intercept',
  '3': 'traffic',
  '4': 'replay',
  '5': 'attack',
  '6': 'scan',
  '7': 'sitemap',
  '8': 'tokens',
  '9': 'tools',
  '0': 'findings',
};

// v0.3.16: focusable elements where Ctrl+F / Ctrl+L should fall through
// to the native input behavior (or, in our case, focus the module-local
// search input) rather than be hijacked globally. We dispatch a
// `ws-shortcut` CustomEvent so modules can opt in without us hard-coding
// every search-input ref here.
function inEditable(t: EventTarget | null): boolean {
  if (!(t instanceof HTMLElement)) return false;
  const tag = t.tagName;
  return tag === 'INPUT' || tag === 'TEXTAREA' || t.isContentEditable;
}

export function useKeyboardShortcuts() {
  const setActiveModule = useAppStore((s) => s.setActiveModule);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'F1') {
        e.preventDefault();
        setActiveModule('docs');
        return;
      }

      // Ctrl+Shift+K — clear the active module (Traffic, Logger, …).
      if (e.ctrlKey && e.shiftKey && (e.key === 'K' || e.key === 'k')) {
        e.preventDefault();
        window.dispatchEvent(new CustomEvent('ws-shortcut', { detail: { action: 'clear' } }));
        return;
      }

      if (e.ctrlKey && !e.shiftKey && !e.altKey) {
        const target = MODULE_KEYS[e.key];
        if (target) {
          e.preventDefault();
          setActiveModule(target);
          return;
        }
        if (e.key === ',') {
          e.preventDefault();
          setActiveModule('settings');
          return;
        }
        // Ctrl+L — focus the active module's search/filter input.
        if (e.key === 'l' || e.key === 'L') {
          e.preventDefault();
          window.dispatchEvent(new CustomEvent('ws-shortcut', { detail: { action: 'focus-search' } }));
          return;
        }
        // Ctrl+E — re-send / repeat last request (Repeater + Intercept).
        if (e.key === 'e' || e.key === 'E') {
          if (inEditable(e.target)) return;
          e.preventDefault();
          window.dispatchEvent(new CustomEvent('ws-shortcut', { detail: { action: 'resend' } }));
          return;
        }
        // Ctrl+F — let the browser-native find work in editable inputs
        // (Repeater body, request templates), otherwise act like Ctrl+L.
        if (e.key === 'f' || e.key === 'F') {
          if (inEditable(e.target)) return;
          e.preventDefault();
          window.dispatchEvent(new CustomEvent('ws-shortcut', { detail: { action: 'focus-search' } }));
          return;
        }
      }
    };

    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [setActiveModule]);
}
