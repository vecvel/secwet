import { useId, type ReactNode } from "react";
import { Badge } from "./Badge";
import styles from "./ChoiceCards.module.css";

export interface Choice<T extends string> {
  value: T;
  title: string;
  description: ReactNode;
  /** Short hint shown next to the title, for example "Lost or stolen". */
  hint?: string;
}

interface Props<T extends string> {
  label: string;
  value: T;
  options: Choice<T>[];
  onChange: (value: T) => void;
  disabled?: boolean;
}

/** Radio-style option cards. The selected card gets the subtle accent tint; borders never change. */
export function ChoiceCards<T extends string>({ label, value, options, onChange, disabled }: Props<T>) {
  const name = useId();
  return (
    <div role="radiogroup" aria-label={label} className={styles.group}>
      {options.map((o) => {
        const selected = o.value === value;
        const titleId = `${name}-${o.value}-title`;
        const descId = `${name}-${o.value}-desc`;
        const hintId = `${name}-${o.value}-hint`;
        return (
          <label
            key={o.value}
            className={[styles.card, selected && styles.selected, disabled && styles.disabled].filter(Boolean).join(" ")}
          >
            <input
              type="radio"
              name={name}
              value={o.value}
              checked={selected}
              disabled={disabled}
              onChange={() => onChange(o.value)}
              aria-labelledby={titleId}
              aria-describedby={o.hint ? `${hintId} ${descId}` : descId}
              className="visually-hidden"
            />
            <span className={styles.radio} aria-hidden="true">
              {selected && <span className={styles.radioDot} />}
            </span>
            <span className={styles.text}>
              <span className={styles.titleRow}>
                <span id={titleId} className={styles.title}>
                  {o.title}
                </span>
                {o.hint && (
                  <span id={hintId}>
                    <Badge>{o.hint}</Badge>
                  </span>
                )}
              </span>
              <span id={descId} className={styles.description}>
                {o.description}
              </span>
            </span>
          </label>
        );
      })}
    </div>
  );
}
