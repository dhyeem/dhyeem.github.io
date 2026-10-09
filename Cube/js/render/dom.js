// Small DOM/HTML helpers + client-side masking of numbers and IPs (display only).

export const esc = (s) =>
  String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const h = (strings, ...vals) => strings.reduce((a, s, i) => a + s + (i < vals.length ? vals[i] : ''), '');

/** Mask text: IPv4 -> a.b.x.x, long digit strings (numbers) keep first 4 chars. */
export function maskString(s) {
  return String(s)
    .replace(/\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b/g, '$1.$2.x.x')
    .replace(/\+?\d{7,}/g, (m) => m.slice(0, 4) + 'x'.repeat(m.length - 4));
}

/** Walk the DOM under root and mask text nodes (skips elements with class "nomask"). */
export function maskDom(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: (n) => (n.parentElement && n.parentElement.closest('.nomask, textarea, input, select, script, style') ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT),
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach((n) => {
    const m = maskString(n.nodeValue);
    if (m !== n.nodeValue) n.nodeValue = m;
  });
}

export const chip = (cls, text) => `<span class="chip ${cls}">${esc(text)}</span>`;
export const pre = (lines, cls = '') => `<pre class="${cls}">${esc(Array.isArray(lines) ? lines.join('\n') : lines)}</pre>`;
