/**
 * MOSCA — terminal styling
 * ========================
 * Zero-dependency ANSI helpers with respect for NO_COLOR and non-TTY output.
 */

const enabled = (() => {
  if (process.env.NO_COLOR) return false;
  if (process.env.FORCE_COLOR === '0') return false;
  if (process.env.FORCE_COLOR) return true;
  return Boolean(process.stdout && process.stdout.isTTY);
})();

const wrap = (open, close) => (s) => (enabled ? `\u001b[${open}m${s}\u001b[${close}m` : String(s));

export const c = {
  bold: wrap(1, 22),
  dim: wrap(2, 22),
  italic: wrap(3, 23),
  underline: wrap(4, 24),
  red: wrap(31, 39),
  green: wrap(32, 39),
  yellow: wrap(33, 39),
  blue: wrap(34, 39),
  magenta: wrap(35, 39),
  cyan: wrap(36, 39),
  white: wrap(37, 39),
  gray: wrap(90, 39),
  brightRed: wrap(91, 39),
  brightGreen: wrap(92, 39),
  brightYellow: wrap(93, 39),
  brightBlue: wrap(94, 39),
  brightMagenta: wrap(95, 39),
  brightCyan: wrap(96, 39),
  bgRed: wrap(41, 49),
  bgGreen: wrap(42, 49),
  bgYellow: wrap(43, 49),
  bgBlue: wrap(44, 49),
  bgMagenta: wrap(45, 49),
  bgCyan: wrap(46, 49),
};

export const isColorEnabled = enabled;

/** Colour a severity label. */
export function severityColor(sev) {
  switch (sev) {
    case 'critical': return c.bgRed(c.white(c.bold(' CRITICAL ')));
    case 'high': return c.brightRed(c.bold(' HIGH '));
    case 'medium': return c.brightYellow(' MEDIUM ');
    case 'low': return c.cyan(' LOW ');
    default: return c.gray(' INFO ');
  }
}

/** Colour a quantum status. */
export function quantumColor(status, text) {
  switch (status) {
    case 'safe': return c.green(text);
    case 'weakened': return c.yellow(text);
    case 'broken': return c.red(text);
    default: return c.gray(text);
  }
}

/** A horizontal rule sized to the terminal. */
export function rule(width = Math.min(process.stdout.columns || 80, 100), char = '─') {
  return c.gray(char.repeat(width));
}

/** Pad a string accounting for ANSI escape sequences. */
export function padEnd(str, width) {
  const visible = String(str).replace(/\u001b\[[0-9;]*m/g, '').length;
  return String(str) + ' '.repeat(Math.max(0, width - visible));
}

/** Pad from the start, ANSI-aware. */
export function padStart(str, width) {
  const visible = String(str).replace(/\u001b\[[0-9;]*m/g, '').length;
  return ' '.repeat(Math.max(0, width - visible)) + String(str);
}

/** Render a 0-100 score as a coloured bar. */
export function scoreBar(score, width = 24) {
  const filled = Math.round((score / 100) * width);
  const color = score >= 75 ? c.green : score >= 50 ? c.yellow : score >= 25 ? c.brightYellow : c.red;
  return color('█'.repeat(filled)) + c.gray('░'.repeat(width - filled));
}
