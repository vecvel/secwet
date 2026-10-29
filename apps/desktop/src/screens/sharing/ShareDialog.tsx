import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Button } from "../../components/Button";
import { Dialog } from "../../components/Dialog";
import { Icon } from "../../components/Icon";
import { SelectControl, SelectField, TextField } from "../../components/Field";
import { Notice } from "../../components/Notice";
import {
  ROLE_DESCRIPTIONS,
  ROLE_LABELS,
  SHARING_BLOCK_COPY,
  draftToGrants,
  grantsOutside,
  grantsToDraft,
  hasReadableGrant,
  inheritedRole,
  isShareableSpace,
  isValidEmail,
  nodeKey,
  sharingBlock,
  type GrantDraft,
} from "../../lib/access";
import {
  api,
  formatUiError,
  type GrantInput,
  type InviteResultDto,
  type MemberView,
  type ScopeNodeView,
  type SpaceView,
  type TreeNodeKind,
  type TreeRole,
} from "../../lib/api";
import { appStore } from "../../lib/store";
import { usePlanStatus } from "../../lib/usePlan";
import styles from "./ShareDialog.module.css";

const ROLES: TreeRole[] = ["admin", "editor", "viewer", "no_access"];

interface Props {
  spaces: SpaceView[];
  /** Space to share. Null or missing shows a space picker (Members > Invite). */
  initialSpaceId?: string | null;
  /** Node to preselect as Viewer, for example an item or the current environment. */
  focus?: { kind: TreeNodeKind; id: string } | null;
  /** When set, edits this member's access instead of inviting someone new. */
  member?: MemberView | null;
  /** Spaces this device may share; defaults to every space except Personal. */
  canShareSpace?: (space: SpaceView) => boolean;
  onClose: () => void;
  onInvited?: (result: InviteResultDto, email: string) => void;
  onSaved?: (member: MemberView) => void;
}

interface ItemBlock {
  item: ScopeNodeView;
  /** General first, then environments. */
  children: ScopeNodeView[];
}

interface GroupBlock {
  group: ScopeNodeView;
  items: ItemBlock[];
}

/** Groups the depth-first scope list into space, groups, items and their scopes. */
function groupTree(nodes: ScopeNodeView[]): { space: ScopeNodeView | null; groups: GroupBlock[] } {
  const space = nodes.find((n) => n.kind === "space") ?? null;
  const groups: GroupBlock[] = [];
  for (const n of nodes) {
    if (n.kind === "group") {
      groups.push({ group: n, items: [] });
    } else if (n.kind === "item") {
      groups[groups.length - 1]?.items.push({ item: n, children: [] });
    } else if (n.kind === "general" || n.kind === "environment") {
      const g = groups[groups.length - 1];
      g?.items[g.items.length - 1]?.children.push(n);
    }
  }
  return { space, groups };
}

/** One line describing an item's General and environment roles. */
function itemSummary(children: ScopeNodeView[], draft: GrantDraft): string {
  let restricted = 0;
  let custom = 0;
  for (const c of children) {
    const role = draft[nodeKey(c)];
    if (role === "no_access") restricted++;
    else if (role) custom++;
  }
  const parts: string[] = [];
  if (restricted) parts.push(`${restricted} restricted`);
  if (custom) parts.push(`${custom} set separately`);
  if (parts.length) return parts.join(", ");
  const envs = children.filter((c) => c.kind === "environment").length;
  if (envs === 0) return "General inherits";
  return `General and ${envs} ${envs === 1 ? "environment" : "environments"} inherit`;
}

export function ShareDialog({
  spaces,
  initialSpaceId = null,
  focus = null,
  member = null,
  canShareSpace = isShareableSpace,
  onClose,
  onInvited,
  onSaved,
}: Props) {
  const editing = Boolean(member);
  const pickSpace = !initialSpaceId;
  const shareable = useMemo(
    () => spaces.filter((s) => isShareableSpace(s) && canShareSpace(s)),
    [spaces, canShareSpace]
  );

  const [spaceId, setSpaceId] = useState<string>(() =>
    initialSpaceId && shareable.some((s) => s.id === initialSpaceId) ? initialSpaceId : shareable[0]?.id ?? ""
  );
  const [showRoles, setShowRoles] = useState(false);
  const space = spaces.find((s) => s.id === spaceId) ?? null;
  const spaceBlocked = !space || !isShareableSpace(space);

  const [email, setEmail] = useState(member?.email ?? "");
  const [emailError, setEmailError] = useState<string>();
  // Per-space state so switching spaces in "Change access" never drops edits.
  const [nodesBySpace, setNodesBySpace] = useState<Record<string, ScopeNodeView[]>>({});
  const [drafts, setDrafts] = useState<Record<string, GrantDraft>>({});
  const [touched, setTouched] = useState<Record<string, boolean>>({});
  const [loadingNodes, setLoadingNodes] = useState(false);
  const [scopeError, setScopeError] = useState<string>();
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<InviteResultDto | null>(null);
  const [copied, setCopied] = useState(false);
  // Invites and access changes travel through the sync relay (Pro). Explain
  // instead of failing when the plan or sync does not allow it.
  const planBlock = sharingBlock(usePlanStatus());

  const nodes = nodesBySpace[spaceId] ?? [];
  const tree = useMemo(() => groupTree(nodes), [nodes]);
  /** User's expand or collapse choice per item; otherwise items with a role
      set on General or an environment start expanded. */
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  function roleSelect(node: ScopeNodeView) {
    const explicit = draft[nodeKey(node)];
    const inherited = inheritedRole(nodes, draft, node, keptGrants);
    const isRoot = node.kind === "space";
    return (
      <div className={styles.roleSelect}>
        <SelectControl
          aria-label={`Role for ${node.label}`}
          value={explicit ?? ""}
          disabled={busy}
          onChange={(e) => setRole(node, e.target.value as TreeRole | "")}
        >
          <option value="">
            {isRoot && inherited === "no_access" ? "Not shared" : `Inherit (${ROLE_LABELS[inherited]})`}
          </option>
          {ROLES.filter((r) => !(isRoot && r === "no_access")).map((r) => (
            <option key={r} value={r}>
              {ROLE_LABELS[r]}
            </option>
          ))}
        </SelectControl>
      </div>
    );
  }
  const draft = drafts[spaceId] ?? {};

  /** Every node of every loaded space, so kept grants exclude all of them. */
  const loadedNodes = useMemo(() => Object.values(nodesBySpace).flat(), [nodesBySpace]);
  /** The member's grants outside every loaded space (other spaces, the workspace). */
  const keptGrants: GrantInput[] = useMemo(
    () => (member ? grantsOutside(loadedNodes, member.grants) : []),
    [member, loadedNodes]
  );

  useEffect(() => {
    if (!spaceId || spaceBlocked || nodesBySpace[spaceId]) return;
    let cancelled = false;
    setLoadingNodes(true);
    setScopeError(undefined);
    api
      .scopeNodes(spaceId)
      .then((list) => {
        if (cancelled) return;
        let initial: GrantDraft;
        if (member) {
          initial = grantsToDraft(list, member.grants);
        } else if (focus && list.some((n) => n.kind === focus.kind && n.id === focus.id)) {
          initial = { [nodeKey(focus)]: "viewer" };
        } else {
          const root = list.find((n) => n.kind === "space");
          initial = root ? { [nodeKey(root)]: "viewer" } : {};
        }
        // Clear loading before storing the nodes: storing them re-runs this
        // effect, whose cleanup marks this request cancelled.
        setLoadingNodes(false);
        setNodesBySpace((prev) => ({ ...prev, [spaceId]: list }));
        setDrafts((prev) => (prev[spaceId] ? prev : { ...prev, [spaceId]: initial }));
      })
      .catch((err) => {
        if (cancelled) return;
        setLoadingNodes(false);
        setError(formatUiError(err, "Couldn't load this space."));
      });
    return () => {
      cancelled = true;
    };
    // focus and member are fixed for the lifetime of the dialog
  }, [spaceId, spaceBlocked, nodesBySpace]);

  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 4000);
    return () => clearTimeout(t);
  }, [copied]);

  function setRole(node: ScopeNodeView, role: TreeRole | "") {
    setScopeError(undefined);
    setTouched((prev) => ({ ...prev, [spaceId]: true }));
    setDrafts((prev) => {
      const next = { ...(prev[spaceId] ?? {}) };
      if (role === "") delete next[nodeKey(node)];
      else next[nodeKey(node)] = role;
      return { ...prev, [spaceId]: next };
    });
  }

  /**
   * Spaces whose drafts are submitted. Editing: every loaded space (untouched ones equal the
   * member's current grants). Inviting: the open space plus any the user changed, so a default
   * "Viewer" on a space the user only glanced at is never granted.
   */
  function submittedSpaceIds(): string[] {
    return Object.keys(nodesBySpace).filter((id) => {
      const sp = spaces.find((x) => x.id === id);
      if (!sp || !isShareableSpace(sp)) return false;
      return Boolean(member) || id === spaceId || touched[id];
    });
  }

  async function submit(e?: FormEvent) {
    e?.preventDefault();
    if (spaceBlocked || busy || planBlock) return;
    let ok = true;
    if (!editing && !isValidEmail(email)) {
      setEmailError("Enter a valid email address.");
      ok = false;
    }
    const ids = submittedSpaceIds();
    const readable =
      ids.some((id) => hasReadableGrant(nodesBySpace[id], drafts[id] ?? {}, keptGrants)) ||
      keptGrants.some((g) => g.role !== "no_access");
    if (!readable) {
      setScopeError("Give access to at least one part of this space.");
      ok = false;
    }
    if (!ok) return;

    const grants = [...keptGrants, ...ids.flatMap((id) => draftToGrants(nodesBySpace[id], drafts[id] ?? {}))];
    setBusy(true);
    setError(null);
    try {
      if (member) {
        const updated = await api.memberSetGrants(member.member_id, grants);
        onSaved?.(updated);
        onClose();
      } else {
        const res = await api.memberInvite(email.trim(), grants);
        appStore.rememberInviteLink(res.invitation_id, res.link);
        setResult(res);
        onInvited?.(res, email.trim());
      }
    } catch (err) {
      setError(formatUiError(err, editing ? "Couldn't save access. Try again." : "Couldn't create the invite. Try again."));
    } finally {
      setBusy(false);
    }
  }

  /** The link carries the invite token, so it goes through the auto-clearing Rust clipboard. */
  async function copyLink() {
    if (!result) return;
    setError(null);
    try {
      await api.inviteLinkCopy(result.invitation_id);
      setCopied(true);
    } catch (err) {
      setError(formatUiError(err, "Couldn't copy the link. Select it and copy it manually."));
    }
  }

  if (result) {
    return (
      <Dialog
        title="Invite created"
        description={`Send this link to ${email.trim()}. It works once and expires in 7 days.`}
        onClose={onClose}
        footer={
          <Button variant="primary" onClick={onClose}>
            Done
          </Button>
        }
      >
        <div className={styles.linkRow}>
          <TextField
            label="Invite link"
            readOnly
            value={result.link}
            spellCheck={false}
            onFocus={(e) => e.currentTarget.select()}
          />
          <Button variant="secondary" icon={copied ? "check" : "copy"} className={styles.copyBtn} onClick={copyLink}>
            {copied ? "Copied" : "Copy"}
          </Button>
        </div>
        <span className="visually-hidden" role="status" aria-live="polite">
          {copied ? "Link copied" : ""}
        </span>
        {copied && <p className={styles.hint}>Copied. Clears in 30 seconds.</p>}
        <p className={styles.hint}>
          Secwet doesn't send email. The link is the only way in, so send it somewhere only {email.trim()} can read.
        </p>
        {error && (
          <p className={styles.error} role="alert">
            {error}
          </p>
        )}
      </Dialog>
    );
  }

  const title = editing
    ? `Change access for ${member?.email ?? "invited member"}`
    : space && !pickSpace
      ? `Share ${space.name}`
      : "Invite someone";

  return (
    <Dialog
      title={title}
      description={
        editing
          ? "Choose what they can see and change in each space."
          : "They get their own key. You choose what they can see and change."
      }
      onClose={onClose}
      busy={busy}
      footer={
        <>
          <Button variant="secondary" onClick={onClose} disabled={busy}>
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={() => submit()}
            disabled={busy || spaceBlocked || loadingNodes || planBlock !== null}
          >
            {busy ? (editing ? "Saving…" : "Creating invite…") : editing ? "Save access" : "Create invite"}
          </Button>
        </>
      }
    >
      <form className={styles.form} onSubmit={submit} noValidate>
        {planBlock && (
          <Notice tone="warning" label={SHARING_BLOCK_COPY[planBlock].title}>
            {SHARING_BLOCK_COPY[planBlock].body}
          </Notice>
        )}
        {!editing && (
          <TextField
            label="Email"
            type="email"
            autoComplete="off"
            spellCheck={false}
            placeholder="name@example.com"
            value={email}
            error={emailError}
            disabled={busy}
            onChange={(e) => {
              setEmail(e.target.value);
              if (emailError) setEmailError(undefined);
            }}
          />
        )}

        {(pickSpace || editing) && shareable.length > 0 && (
          <SelectField
            label="Space"
            value={spaceId}
            disabled={busy}
            onChange={(e) => {
              setSpaceId(e.target.value);
              setError(null);
            }}
          >
            {shareable.map((s) => (
              <option key={s.id} value={s.id}>
                {s.name}
              </option>
            ))}
          </SelectField>
        )}

        {spaceBlocked ? (
          <Notice tone="warning" label="No space to share">
            Create a space to share. The Personal space is only for you.
          </Notice>
        ) : (
          <div className={styles.scope}>
            <div className={styles.scopeHeader}>
              <div className={styles.labelRow}>
                <span className={styles.label}>Access</span>
                <button
                  type="button"
                  className={[styles.infoButton, showRoles && styles.infoButtonOpen].filter(Boolean).join(" ")}
                  aria-label="What the roles allow"
                  aria-expanded={showRoles}
                  aria-controls="share-role-legend"
                  onClick={() => setShowRoles((v) => !v)}
                >
                  <Icon name="info" size={14} />
                </button>
              </div>
              <span className={styles.subtle}>Rows inherit from their parent unless you set them.</span>
            </div>
            {showRoles && (
              <dl id="share-role-legend" className={styles.legend}>
                {ROLES.map((r) => (
                  <div key={r} className={styles.legendRow}>
                    <dt>{ROLE_LABELS[r]}</dt>
                    <dd>{ROLE_DESCRIPTIONS[r]}</dd>
                  </div>
                ))}
              </dl>
            )}
            <div className={styles.scopeTree} aria-label="Access by scope" aria-busy={loadingNodes}>
              {loadingNodes && nodes.length === 0 && <p className={styles.loading}>Loading…</p>}
              {tree.space && (
                <div className={styles.card}>
                  <div className={styles.cardRow}>
                    <div className={styles.scopeText}>
                      <span className={styles.scopeName}>{tree.space.label}</span>
                      <span className={styles.subtle}>Whole space</span>
                    </div>
                    {roleSelect(tree.space)}
                  </div>
                </div>
              )}
              {tree.groups.map(({ group, items }) => (
                <section key={nodeKey(group)} className={styles.groupBlock} aria-label={`Group ${group.label}`}>
                  <div className={styles.groupHeader}>
                    <span className={styles.groupName}>Group · {group.label}</span>
                    {roleSelect(group)}
                  </div>
                  {items.map(({ item, children }) => {
                    const key = nodeKey(item);
                    const hasChildRole = children.some((c) => draft[nodeKey(c)]);
                    const open = expanded[key] ?? hasChildRole;
                    const panelId = `share-item-${item.id}`;
                    return (
                      <div key={key} className={styles.card}>
                        <div className={styles.cardRow}>
                          <button
                            type="button"
                            className={styles.itemToggle}
                            aria-expanded={open}
                            aria-controls={panelId}
                            onClick={() => setExpanded((prev) => ({ ...prev, [key]: !open }))}
                          >
                            <span className={styles.chevron} aria-hidden="true">
                              <Icon name={open ? "chevronDown" : "chevronRight"} size={16} />
                            </span>
                            <span className={styles.scopeText}>
                              <span className={styles.scopeName}>{item.label}</span>
                              <span className={styles.subtle}>{itemSummary(children, draft)}</span>
                            </span>
                          </button>
                          {roleSelect(item)}
                        </div>
                        {open && (
                          <ul id={panelId} className={styles.childList}>
                            {children.map((child, i) => (
                              <li key={nodeKey(child)} className={styles.cardRow}>
                                <span className={styles.childLead}>
                                  <span
                                    className={`${styles.thread} ${i === children.length - 1 ? styles.threadEnd : ""}`}
                                    aria-hidden="true"
                                  />
                                  <span className={styles.childName}>{child.label}</span>
                                </span>
                                {roleSelect(child)}
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    );
                  })}
                </section>
              ))}
            </div>
            {scopeError && (
              <p className={styles.error} role="alert">
                {scopeError}
              </p>
            )}
          </div>
        )}

        {error && (
          <p className={styles.error} role="alert">
            {error}
          </p>
        )}
      </form>
    </Dialog>
  );
}
