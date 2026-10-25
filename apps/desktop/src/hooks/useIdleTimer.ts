/**
 * apps/desktop/src/hooks/useIdleTimer.ts
 *
 * Tracks user activity and triggers auto-lock when inactivity exceeds
 * the configured timeout interval.
 */
import { useEffect, useRef } from "react";

export interface IdleTimerOptions {
  timeoutMinutes: number;
  onIdle: () => void | Promise<void>;
  enabled?: boolean;
}

export function useIdleTimer({ timeoutMinutes, onIdle, enabled = true }: IdleTimerOptions) {
  const lastActiveRef = useRef<number>(Date.now());
  const onIdleRef = useRef(onIdle);
  onIdleRef.current = onIdle;

  useEffect(() => {
    if (!enabled) return;

    lastActiveRef.current = Date.now();
    const timeoutMs = Math.max(1, timeoutMinutes) * 60 * 1000;

    let lastHandled = 0;
    const handleActivity = () => {
      const now = Date.now();
      if (now - lastHandled > 1000) {
        lastHandled = now;
        lastActiveRef.current = now;
      }
    };

    // Tracking user activity per specification: mousemove, keydown, pointerdown, scroll
    const events: Array<keyof WindowEventMap> = [
      "mousemove",
      "keydown",
      "pointerdown",
      "scroll",
      "touchstart",
      "focus",
    ];

    events.forEach((e) => window.addEventListener(e, handleActivity, { passive: true }));

    const interval = setInterval(() => {
      const idleTime = Date.now() - lastActiveRef.current;
      if (idleTime >= timeoutMs) {
        onIdleRef.current();
      }
    }, 2000);

    return () => {
      events.forEach((e) => window.removeEventListener(e, handleActivity));
      clearInterval(interval);
    };
  }, [timeoutMinutes, enabled]);
}
