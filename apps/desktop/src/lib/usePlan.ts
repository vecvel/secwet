/**
 * apps/desktop/src/lib/usePlan.ts
 *
 * The real plan of this Secwet (F13), shared by every screen. It comes from
 * the relay entitlement cached in the core; reading it never contacts the
 * relay. Reloads when the backend reports a plan, device or full change.
 */
import { useEffect, useState } from "react";
import { api, type PlanStatusDto } from "./api";

let current: PlanStatusDto | null = null;
const listeners = new Set<(plan: PlanStatusDto | null) => void>();
let subscribed = false;
let inflight: Promise<void> | null = null;

function publish(plan: PlanStatusDto | null) {
  current = plan;
  listeners.forEach((fn) => fn(plan));
}

/** Re-reads the cached plan from the backend (no network). */
export function reloadPlan(): Promise<void> {
  if (!inflight) {
    inflight = api
      .planStatus()
      .then(publish)
      .catch(() => {
        // Locked or not created yet: keep the last known plan.
      })
      .finally(() => {
        inflight = null;
      });
  }
  return inflight;
}

/** Stores a plan returned by planRefresh or planActivate. */
export function setPlanStatus(plan: PlanStatusDto) {
  publish(plan);
}

function subscribeOnce() {
  if (subscribed) return;
  subscribed = true;
  api
    .onSecwetChanged((e) => {
      if (e.scope === "plan" || e.scope === "all" || e.scope === "devices") reloadPlan();
    })
    .catch(() => {
      subscribed = false;
    });
}

/** The plan, or null until it has loaded. */
export function usePlanStatus(): PlanStatusDto | null {
  const [plan, setPlan] = useState<PlanStatusDto | null>(current);
  useEffect(() => {
    listeners.add(setPlan);
    subscribeOnce();
    reloadPlan();
    return () => {
      listeners.delete(setPlan);
    };
  }, []);
  return plan;
}
