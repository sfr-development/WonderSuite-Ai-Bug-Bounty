// Tracks whether the user has seen the changelog for the currently-installed
// version. The sidebar shows a "1" badge until they open the Changelog tab.
//
// Persistence: a single localStorage key remembers the last version the user
// viewed. On every app load we compare it to the version baked into
// package.json — if it doesn't match (fresh install, fresh update), the
// badge is shown until the user opens the tab.

import { create } from 'zustand';
import pkg from '../../package.json';

const STORAGE_KEY = 'ws_last_seen_changelog_version_v1';
const CURRENT_VERSION: string = pkg.version;

interface ChangelogStore {
  /** The currently-installed app version (read from package.json at build time). */
  currentVersion: string;
  /** The version the user last viewed the changelog for. `null` for fresh installs. */
  lastSeenVersion: string | null;
  /** `true` when current !== lastSeen. Drives the sidebar "1" badge. */
  hasUnseenChangelog: boolean;
  /** Call when the user opens the Changelog tab — clears the badge. */
  markAsSeen: () => void;
}

const loadLastSeen = (): string | null => {
  try {
    return localStorage.getItem(STORAGE_KEY);
  } catch {
    return null;
  }
};

export const useChangelogStore = create<ChangelogStore>((set) => {
  const lastSeenVersion = loadLastSeen();
  return {
    currentVersion: CURRENT_VERSION,
    lastSeenVersion,
    hasUnseenChangelog: lastSeenVersion !== CURRENT_VERSION,
    markAsSeen: () => {
      try {
        localStorage.setItem(STORAGE_KEY, CURRENT_VERSION);
      } catch {}
      set({ lastSeenVersion: CURRENT_VERSION, hasUnseenChangelog: false });
    },
  };
});
