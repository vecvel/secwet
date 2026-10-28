import { useCallback, useEffect, useState } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { ChoiceCards } from "../../components/ChoiceCards";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { EmptyState } from "../../components/EmptyState";
import { List, ListRow } from "../../components/List";
import { MoreMenu, type MenuItem } from "../../components/Menu";
import { Notice } from "../../components/Notice";
import { Section } from "../../components/PageHeader";
import { isShareableSpace, permissionsFor, spaceOfGrant, summarizeGrants } from "../../lib/access";
import { api, formatUiError, type MemberStatus, type MemberView, type SpaceView } from "../../lib/api";
import { formatAgo, plural } from "../../lib/format";
import { useStore } from "../../lib/store";
import { useReadOnly } from "../../lib/useAccess";
import { ShareDialog } from "../sharing/ShareDialog";
import styles from "./SettingsScreen.module.css";

const STATUS: Record<MemberStatus, { label: string; tone: "neutral" | "accent" | "success" | "warning" | "danger" }> = {
  invited: { label: "Invited", tone: "warning" },
  accepted: { label: "Joining", tone: "accent" },
  active: { label: "Active", tone: "success" },
  removed: { label: "Removed", tone: "neutral" },
  expired: { label: "Expired", tone: "neutral" },
};

function memberMeta(m: MemberView): string {
  const access = summarizeGrants(m.grants);
  if (m.status === "invited") return `${access}. Invited ${formatAgo(m.invited_at).toLowerCase()}.`;
  if (m.status === "expired") return `${access}. The invite expired.`;
  const devices = m.devices.filter((d) => !d.revoked).length;
  return `${access}. ${plural(devices, "device")}.`;
}

/** Settings > Members: owners and admins see who has access and manage it. */
export function MembersSection() {
  const [state, store] = useStore();
  const readOnly = useReadOnly();
  const [members, setMembers] = useState<MemberView[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [inviting, setInviting] = useState(false);
  const [editing, setEditing] = useState<MemberView | null>(null);
  const [removing, setRemoving] = useState<MemberView | null>(null);
  const [removeMode, setRemoveMode] = useState<"wipe" | "keep">("wipe");
  const [removeBusy, setRemoveBusy] = useState(false);
  const [removeError, setRemoveError] = useState<string | null>(null);
  const [revokingInvite, setRevokingInvite] = useState<MemberView | null>(null);

  const canShareSpace = useCallback(
    (space: SpaceView) => isShareableSpace(space) && permissionsFor(state.access, readOnly, { spaceId: space.id }).canShare,
    [state.access, readOnly]
  );

  const load = useCallback(async () => {
    try {
      setMembers(await api.membersList());
      setError(null);
    } catch (err) {
      setError(formatUiError(err, "Couldn't load members."));
      setMembers((prev) => prev ?? []);
    }
  }, []);

  useEffect(() => {
    load();
    let unlisten: (() => void) | undefined;
    api
      .onSecwetChanged((e) => {
        if (e.scope === "members" || e.scope === "all") load();
      })
      .then((fn) => {
        unlisten = fn;
      });
    return () => unlisten?.();
  }, [load]);

  /** The link carries the invite token, so it goes through the auto-clearing Rust clipboard. */
  async function copyLink(m: MemberView) {
    if (!m.invitation_id) return;
    try {
      await api.inviteLinkCopy(m.invitation_id);
      setNotice("Copied. Clears in 30 seconds.");
    } catch (err) {
      setError(
        formatUiError(err, "Couldn't copy the link.") +
          (String((err as { code?: string })?.code).toLowerCase() === "not_found"
            ? " Revoke the invitation and invite again."
            : "")
      );
    }
  }

  async function remove(m: MemberView, wipe: boolean) {
    setRemoveBusy(true);
    setRemoveError(null);
    try {
      await api.memberRemove(m.member_id, wipe);
      setRemoving(null);
      setNotice(
        wipe
          ? `${m.email ?? "The member"} was removed. Their devices erase this workspace when they next connect.`
          : `${m.email ?? "The member"} was removed. Their devices keep a read-only copy of what was shared.`
      );
      await Promise.all([load(), store.reloadKeyStatus()]);
    } catch (err) {
      setRemoveError(formatUiError(err, "Couldn't remove this member. Try again."));
    } finally {
      setRemoveBusy(false);
    }
  }

  async function revokeInvite(m: MemberView) {
    setRevokingInvite(null);
    if (!m.invitation_id) return;
    try {
      await api.invitationRevoke(m.invitation_id);
      setNotice("Invitation revoked. The link no longer works.");
      await load();
    } catch (err) {
      setError(formatUiError(err, "Couldn't revoke this invitation."));
    }
  }

  function menuFor(m: MemberView): MenuItem[] {
    const items: MenuItem[] = [
      { label: "Change access", icon: "pencil", onSelect: () => setEditing(m) },
    ];
    if (m.status === "invited") {
      if (store.inviteLink(m.invitation_id)) {
        items.push({ label: "Copy invite link", icon: "copy", onSelect: () => copyLink(m) });
      }
      if (m.invitation_id) {
        items.push({
          label: "Revoke invitation",
          icon: "close",
          danger: true,
          separator: true,
          onSelect: () => setRevokingInvite(m),
        });
      }
    } else {
      items.push({
        label: "Remove member",
        icon: "trash",
        danger: true,
        separator: true,
        onSelect: () => {
          setRemoveMode("wipe");
          setRemoveError(null);
          setRemoving(m);
        },
      });
    }
    return items;
  }

  const visible = (members ?? []).filter((m) => m.status !== "removed");

  return (
    <>
      <Section
        title="Members"
        action={
          <Button variant="primary" icon="plus" disabled={readOnly} onClick={() => setInviting(true)}>
            Invite
          </Button>
        }
      >
        {error && (
          <div className={styles.noticeGap}>
            <Notice tone="warning" label="Members">
              {error}
            </Notice>
          </div>
        )}
        {notice && (
          <div className={styles.noticeGap}>
            <Notice
              tone="success"
              label="Done"
              action={
                <Button variant="tertiary" arrow={false} onClick={() => setNotice(null)}>
                  Dismiss
                </Button>
              }
            >
              {notice}
            </Notice>
          </div>
        )}
        {members === null ? (
          <p className={styles.sectionDesc}>Loading members…</p>
        ) : visible.length === 0 ? (
          <EmptyState
            icon="user"
            title="Only you so far"
            body="Invite people to a space. Each person gets their own key and only sees what you share."
          />
        ) : (
          <List label="Members">
            {visible.map((m) => (
              <ListRow
                key={m.member_id}
                muted={m.status === "expired"}
                title={
                  <>
                    {m.email ?? "Invited member"}
                    <Badge tone={STATUS[m.status].tone}>{STATUS[m.status].label}</Badge>
                  </>
                }
                meta={memberMeta(m)}
                trailing={readOnly ? undefined : <MoreMenu label={`Actions for ${m.email ?? "member"}`} items={menuFor(m)} />}
              />
            ))}
          </List>
        )}
      </Section>

      {inviting && (
        <ShareDialog
          spaces={state.spaces}
          canShareSpace={canShareSpace}
          onClose={() => setInviting(false)}
          onInvited={() => load()}
        />
      )}

      {editing && (
        <ShareDialog
          spaces={state.spaces}
          member={editing}
          initialSpaceId={
            editing.grants
              .map((g) => spaceOfGrant(g, state.groups, state.items))
              .find((id) => id && state.spaces.some((s) => s.id === id && canShareSpace(s))) ?? null
          }
          canShareSpace={canShareSpace}
          onClose={() => setEditing(null)}
          onSaved={() => {
            setNotice(`Access for ${editing.email ?? "the member"} updated.`);
            load();
          }}
        />
      )}

      {removing && (
        <ConfirmDialog
          title={`Remove ${removing.email ?? "this member"}?`}
          body={
            <div className={styles.confirmBody}>
              <p>They lose access right away. Shared spaces get new keys, so they can't read changes made from now on.</p>
              <ChoiceCards
                label="What happens to shared data on their devices"
                value={removeMode}
                onChange={setRemoveMode}
                disabled={removeBusy}
                options={[
                  {
                    value: "wipe",
                    title: "Remove and erase",
                    hint: "Recommended",
                    description:
                      "Their devices erase this workspace when they next connect, including anything they kept in it only for themselves. If a device never connects again, it keeps what it has.",
                  },
                  {
                    value: "keep",
                    title: "Remove and keep a read-only copy",
                    description: "Their devices keep a read-only copy of what was shared before now.",
                  },
                ]}
              />
              {removeError && (
                <p className={styles.formError} role="alert">
                  {removeError}
                </p>
              )}
            </div>
          }
          confirmLabel={removeBusy ? "Removing…" : removeMode === "wipe" ? "Remove and erase" : "Remove member"}
          busy={removeBusy}
          onConfirm={() => remove(removing, removeMode === "wipe")}
          onCancel={() => setRemoving(null)}
        />
      )}

      {revokingInvite && (
        <ConfirmDialog
          title="Revoke invitation?"
          body={<p>The invite link for {revokingInvite.email ?? "this person"} stops working.</p>}
          confirmLabel="Revoke invitation"
          onConfirm={() => revokeInvite(revokingInvite)}
          onCancel={() => setRevokingInvite(null)}
        />
      )}
    </>
  );
}
