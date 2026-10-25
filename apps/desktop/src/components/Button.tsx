import type { ButtonHTMLAttributes } from "react";
import { Icon, type IconName } from "./Icon";
import styles from "./Button.module.css";

type Variant = "primary" | "secondary" | "tertiary" | "danger";

interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: Variant;
  icon?: IconName;
  /** Tertiary buttons show a trailing arrow by default. */
  arrow?: boolean;
}

/** primary: filled accent. secondary: outlined. tertiary: text link with arrow. danger: filled, for destructive confirms. */
export function Button({ variant = "secondary", icon, arrow, className, children, type = "button", ...rest }: ButtonProps) {
  const showArrow = arrow ?? variant === "tertiary";
  return (
    <button type={type} className={[styles.button, styles[variant], className].filter(Boolean).join(" ")} {...rest}>
      {icon && <Icon name={icon} />}
      <span>{children}</span>
      {showArrow && <Icon name="arrowRight" size={14} />}
    </button>
  );
}

interface IconButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  icon: IconName;
  label: string;
}

export function IconButton({ icon, label, className, type = "button", ...rest }: IconButtonProps) {
  return (
    <button type={type} aria-label={label} title={label} className={[styles.iconButton, className].filter(Boolean).join(" ")} {...rest}>
      <Icon name={icon} />
    </button>
  );
}
