import { useEffect, useRef, useCallback } from 'react';

/**
 * A visibility-aware interval hook that pauses polling when the browser tab
 * is not visible (minimized, or switched to another tab). This dramatically
 * reduces CPU and network usage for background tabs.
 *
 * Also stops polling when the component unmounts.
 */
export function useVisibilityAwareInterval(
  callback: () => void | Promise<void>,
  delay: number,
  enabled: boolean = true,
) {
  const savedCallback = useRef(callback);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    savedCallback.current = callback;
  }, [callback]);

  const start = useCallback(() => {
    if (intervalRef.current !== null) return; // already running
    intervalRef.current = setInterval(() => {
      savedCallback.current();
    }, delay);
  }, [delay]);

  const stop = useCallback(() => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  useEffect(() => {
    if (!enabled) {
      stop();
      return;
    }

    if (!document.hidden) {
      start();
    }

    const handleVisibilityChange = () => {
      if (document.hidden) {
        stop();
      } else {
        savedCallback.current();
        start();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);

    return () => {
      stop();
      document.removeEventListener('visibilitychange', handleVisibilityChange);
    };
  }, [enabled, start, stop]);
}
