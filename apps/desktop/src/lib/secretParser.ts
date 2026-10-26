/**
 * apps/desktop/src/lib/secretParser.ts
 *
 * Robust key-value parser for environment variables, credentials, and configuration blocks.
 * Supports:
 * - KEY=VALUE, KEY: VALUE, KEY:VALUE
 * - Single, double, and backtick quoted keys and values
 * - Preserves internal colons, commas, semicolons, and quotes inside values
 * - Semicolon and comma record separators outside of quotes
 * - Shell comments (#, //) and 'export ' prefixes
 */

export interface ParsedSecretEntry {
  name: string;
  value: string;
}

export function parseSecretText(raw: string): ParsedSecretEntry[] {
  if (!raw || !raw.trim()) return [];

  const entries: ParsedSecretEntry[] = [];
  const text = raw.replace(/\r\n/g, "\n").replace(/\r/g, "\n");

  const chunks: string[] = [];
  let current: string[] = [];
  let inQuote: string | null = null;
  let i = 0;
  const len = text.length;

  while (i < len) {
    const ch = text[i];

    // Handle escaped characters inside quotes
    if (inQuote && ch === "\\" && i + 1 < len) {
      current.push(ch);
      current.push(text[i + 1]);
      i += 2;
      continue;
    }

    if (inQuote) {
      current.push(ch);
      if (ch === inQuote) {
        inQuote = null;
      }
    } else {
      if (ch === '"' || ch === "'" || ch === "`") {
        inQuote = ch;
        current.push(ch);
      } else if (ch === "\n" || ch === ";") {
        const chunkStr = current.join("").trim();
        if (chunkStr) chunks.push(chunkStr);
        current = [];
      } else if (ch === ",") {
        // If comma separates two key-value pairs, split; otherwise keep as part of value
        const remainder = text.slice(i + 1).trimStart();
        if (/^(?:[A-Za-z_][A-Za-z0-9_.-]*|["'`][^"'`]+["'`])\s*[:=]/.test(remainder)) {
          const chunkStr = current.join("").trim();
          if (chunkStr) chunks.push(chunkStr);
          current = [];
        } else {
          current.push(ch);
        }
      } else {
        current.push(ch);
      }
    }
    i++;
  }

  if (current.length > 0) {
    const chunkStr = current.join("").trim();
    if (chunkStr) chunks.push(chunkStr);
  }

  for (let chunk of chunks) {
    chunk = chunk.trim();
    if (!chunk) continue;

    // Ignore comment lines
    if (chunk.startsWith("#") || chunk.startsWith("//")) continue;

    // Strip shell 'export '
    if (chunk.startsWith("export ")) {
      chunk = chunk.slice(7).trim();
    }

    if (!chunk) continue;

    let key: string | null = null;
    let valStr: string | null = null;

    const firstCh = chunk[0];
    if (firstCh === '"' || firstCh === "'" || firstCh === "`") {
      // Key is quoted
      const endQuote = chunk.indexOf(firstCh, 1);
      if (endQuote !== -1) {
        key = chunk.slice(1, endQuote).trim();
        const rest = chunk.slice(endQuote + 1).trim();
        if (rest && (rest[0] === "=" || rest[0] === ":")) {
          valStr = rest.slice(1).trim();
        }
      }
    } else {
      // Key is unquoted - find first '=' or ':'
      const eqPos = chunk.indexOf("=");
      const colPos = chunk.indexOf(":");

      let sepPos = -1;
      if (eqPos !== -1 && colPos !== -1) {
        sepPos = Math.min(eqPos, colPos);
      } else if (eqPos !== -1) {
        sepPos = eqPos;
      } else if (colPos !== -1) {
        sepPos = colPos;
      }

      if (sepPos !== -1) {
        key = chunk.slice(0, sepPos).trim();
        valStr = chunk.slice(sepPos + 1).trim();
      }
    }

    if (key && valStr !== null) {
      let val = valStr;

      // Extract quoted value (matching first quote to last matching quote before end of entry)
      if (valStr.length >= 2 && (valStr[0] === '"' || valStr[0] === "'" || valStr[0] === "`")) {
        const q = valStr[0];
        const lastQ = valStr.lastIndexOf(q);
        if (lastQ > 0) {
          val = valStr.slice(1, lastQ);
        } else {
          val = valStr.slice(1);
        }
      } else {
        // Strip trailing comma or semicolon if present
        if (val.endsWith(",") || val.endsWith(";")) {
          val = val.slice(0, -1).trim();
        }
      }

      entries.push({ name: key, value: val });
    }
  }

  return entries;
}
