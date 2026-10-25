import { useState } from "react";
import { Badge } from "../../components/Badge";
import { Button } from "../../components/Button";
import { SelectControl } from "../../components/Field";
import { List, ListRow } from "../../components/List";
import { PageHeader, Section } from "../../components/PageHeader";
import type { Plan } from "../../data/mock";
import { CLI_COMMAND } from "../overview/OverviewScreen";
import { PlanDialog } from "../PlanDialog";
import styles from "./SettingsScreen.module.css";

export type ThemePreference = "system" | "light" | "dark";

interface Props {
  plan: Plan;
  onPlanChange: (plan: Plan) => void;
  theme: ThemePreference;
  onThemeChange: (t: ThemePreference) => void;
  lockMinutes: number;
  onLockMinutesChange: (m: number) => void;
  onCliCopied: () => void;
}


export function SettingsScreen({ plan, onPlanChange, theme, onThemeChange, lockMinutes, onLockMinutesChange, onCliCopied }: Props) {
  const [comparing, setComparing] = useState(false);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  async function copyCli() {
    try {
      await navigator.clipboard.writeText(CLI_COMMAND);
      setCopyState("copied");
      onCliCopied();
    } catch {
      setCopyState("failed");
    }
  }

  return (
    <div className={styles.screen}>
      <PageHeader title="Settings" subtitle="Preferences for this device. Nothing here is sent anywhere." />

      <Section title="Plan">
        <List>
          <ListRow
            title={
              <>
                {plan === "pro" ? "Pro" : "Free"}
                <Badge tone="accent">Current plan</Badge>
              </>
            }
            meta={plan === "pro" ? "Sync across every device you approve." : "Unlimited local secrets on this device."}
            trailing={
              <Button variant="tertiary" onClick={() => setComparing(true)}>
                Compare plans
              </Button>
            }
          />
        </List>
      </Section>

      <Section title="This device">
        <List>
          <ListRow
            title="Appearance"
            meta="System follows your operating system's light or dark setting."
            trailing={
              <div className={styles.select}>
                <SelectControl aria-label="Appearance" value={theme} onChange={(e) => onThemeChange(e.target.value as ThemePreference)}>
                  <option value="system">System</option>
                  <option value="light">Light</option>
                  <option value="dark">Dark</option>
                </SelectControl>
              </div>
            }
          />
          <ListRow
            title="Lock vault after"
            meta="Idle time before revealed values hide and the vault locks."
            trailing={
              <div className={styles.select}>
                <SelectControl aria-label="Lock vault after" value={lockMinutes} onChange={(e) => onLockMinutesChange(Number(e.target.value))}>
                  <option value={5}>5 minutes</option>
                  <option value={15}>15 minutes</option>
                  <option value={30}>30 minutes</option>
                  <option value={60}>1 hour</option>
                </SelectControl>
              </div>
            }
          />
        </List>
      </Section>

      <Section title="Command line">
        <List>
          <ListRow
            title="Run a command with secrets as environment variables"
            meta={<code className={styles.code}>{CLI_COMMAND}</code>}
            trailing={
              <Button variant="secondary" icon={copyState === "copied" ? "check" : "copy"} onClick={copyCli}>
                {copyState === "copied" ? "Copied" : "Copy"}
              </Button>
            }
          />
        </List>
        {copyState === "failed" && <p className={styles.hint}>Copy isn't available here. Select the command and copy it manually.</p>}
      </Section>

      {import.meta.env.DEV && (
        <Section title="Development build only">
          <List>
            <ListRow
              title="Simulate plan"
              meta="Switches the mock data between Free and Pro to preview both."
              trailing={
                <div className={styles.select}>
                  <SelectControl aria-label="Simulate plan" value={plan} onChange={(e) => onPlanChange(e.target.value as Plan)}>
                    <option value="free">Free</option>
                    <option value="pro">Pro</option>
                  </SelectControl>
                </div>
              }
            />
          </List>
        </Section>
      )}

      {comparing && <PlanDialog plan={plan} onClose={() => setComparing(false)} />}
    </div>
  );
}
