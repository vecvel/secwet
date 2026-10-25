import { useId, type InputHTMLAttributes } from "react";
import { Icon } from "./Icon";
import styles from "./Checkbox.module.css";

export function Checkbox({ label, ...rest }: { label: string } & Omit<InputHTMLAttributes<HTMLInputElement>, "type">) {
  const id = useId();
  return (
    <label htmlFor={id} className={styles.wrap}>
      <span className={styles.box}>
        <input id={id} type="checkbox" className={styles.input} {...rest} />
        <span className={styles.mark}>
          <Icon name="check" size={12} />
        </span>
      </span>
      <span>{label}</span>
    </label>
  );
}
