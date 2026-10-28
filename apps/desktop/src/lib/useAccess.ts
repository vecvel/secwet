/**
 * apps/desktop/src/lib/useAccess.ts
 *
 * React bindings for the pure helpers in access.ts.
 */
import { useMemo } from "react";
import { isReadOnly, permissionsFor, type NodePath, type Permissions } from "./access";
import { useStore } from "./store";

/** Permissions at `path` for this device, including the read-only archive state. */
export function usePermissions(path: NodePath): Permissions {
  const [state] = useStore();
  const readOnly = isReadOnly(state.linkStatus);
  const { spaceId, groupId, itemId, environmentId, general } = path;
  return useMemo(
    () => permissionsFor(state.access, readOnly, { spaceId, groupId, itemId, environmentId, general }),
    [state.access, readOnly, spaceId, groupId, itemId, environmentId, general]
  );
}

/** True when this device was unlinked and the store is a read-only archive. */
export function useReadOnly(): boolean {
  const [state] = useStore();
  return isReadOnly(state.linkStatus);
}
