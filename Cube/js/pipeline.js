// Pipeline: raw pasted texts -> parsed data -> calls with analysis. Pure (no DOM), shared by UI and tests.
import { cleanLog, splitBlocks } from './parsers/clean.js';
import { parseSipMessages } from './parsers/ccsip.js';
import { parseCcapi, parseSyslogEvents } from './parsers/ccapi.js';
import { parseConfig } from './parsers/config.js';
import { parseDialPeerSummary, parseDialplanNumber, parseVoipTrace } from './parsers/summary.js';
import { buildCalls } from './engine/correlate.js';
import { analyzeCall, mergeSummary } from './engine/diagnose.js';

export function runAnalysis(texts, itsp) {
  const lines = cleanLog(texts.debug || '');
  const blocks = splitBlocks(lines);
  const sip = parseSipMessages(blocks);
  const ccapi = parseCcapi(blocks);
  const syslog = parseSyslogEvents(blocks);
  const trace = parseVoipTrace(texts.trace || '');
  let cfg = texts.config && texts.config.trim() ? parseConfig(texts.config) : null;
  if (cfg && !cfg.dialPeers.length) cfg.noDialPeers = true;
  const rows = parseDialPeerSummary(texts.summary || '');
  if (rows.length) cfg = mergeSummary(cfg, rows);
  const dialplan = parseDialplanNumber(texts.dialplan || '');
  const built = buildCalls(sip, ccapi, syslog, trace);
  const analyses = new Map();
  for (const c of built.calls) analyses.set(c.id, analyzeCall(c, { cfg, itsp, dialplan }));
  return {
    cfg,
    itsp,
    dialplan,
    calls: built.calls,
    keepalives: built.keepalives,
    analyses,
    stats: { lines: lines.length, blocks: blocks.length, sip: sip.length, ccapi: ccapi.length, syslog: syslog.length, trace: trace.length, calls: built.calls.length, orphanCcapi: built.orphanCcapi.length },
  };
}
