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

export function useKeyboardShortcuts() {
  const setActiveModule = useAppStore((s) => s.setActiveModule);

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
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
      }
    };

    window.addEventListener('keydown', handler);
    return () => window.removeEventListener('keydown', handler);
  }, [setActiveModule]);
}
