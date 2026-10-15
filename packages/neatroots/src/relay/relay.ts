import zlib from "node:zlib";
import crypto from "node:crypto";
import type { Roots } from "../core.js";
import { encodeTraceRequest } from "../otlp/codec.js";
import { plainToAny, type KeyValue, type OtlpSpan, type ResourceSpansBatch } from "../otlp/types.js";
import { COMPLETE_MARKER } from "../semantics/view.js";
import { compileRules, redactBatches, type RedactionHit } from "./redact.js";
import { getCloudKey } from "./keychain.js";
import { projectSettings } from "../config.js";
import type { ForwardRow } from "../types.js";
import { log } from "../util/log.js";
import { VERSION } from "../version.js";

export interface ForwardPreview {
  trace_ids: string[];
  span_count: number;
  redactions: { kind: string; count: number; samples: { where: string; sample: string }[] }[];
  endpoint: string;
  has_key: boolean;
}

/**
 * The cloud relay. neatroots reaches Neatlogs Cloud exactly the way an SDK does: OTLP/protobuf
 * to the public ingest endpoint with the user's own x-api-key. Stored spans are re-exported
 * without loss, redacted first, closed with the public neatlogs.trace.complete marker, and
 * carry neatroots findings as neatroots.* attributes.
 */
export class Relay {
  constructor(private readonly roots: Roots) {
    roots.bus.on("trace", (u) => {
      if (!u.rootEnded && !u.completed) return;
      const run = roots.store.getRun(u.traceId);
      if (!run || run.doctor || !run.project) return;
      if (!projectSettings(roots.config, run.project).forward) return;
      void this.autoForward(u.traceId);
    });
  }

  private pendingAuto = new Set<string>();

  private async autoForward(traceId: string): Promise<void> {
    if (this.pendingAuto.has(traceId)) return;
    this.pendingAuto.add(traceId);
    try {
      // Let checks finish so findings travel with the run.
      await new Promise((r) => setTimeout(r, 1500));
      if (this.roots.engine) await this.roots.engine.waitIdle(traceId, 120_000);
      if (this.roots.store.forwardedTraceIds().has(traceId)) return;
      const res = await this.forward([traceId], "auto");
      if (res.status !== "ok") log.warn(`auto-forward of ${traceId.slice(0, 8)} failed: ${res.error}`);
    } finally {
      this.pendingAuto.delete(traceId);
    }
  }

  endpoint(): string {
    return this.roots.config.cloud.endpoint.replace(/\/+$/, "").replace(/\/v1\/traces$/, "");
  }

  private prepared(traceIds: string[]): { batches: ResourceSpansBatch[]; hits: RedactionHit[]; markers: ResourceSpansBatch[]; spanCount: number } {
    const raw = this.roots.store.batchesForTraces(traceIds);
    const withFindings = this.attachFindings(raw, traceIds);
    const rules = compileRules(this.roots.config.cloud.redactPatterns);
    const { batches, hits } = redactBatches(withFindings, rules);
    // Markers go in a second request after their roots, as the SDKs send them.
    const main: ResourceSpansBatch[] = [];
    const markers: ResourceSpansBatch[] = [];
    for (const b of batches) {
      const normal = b.spans.filter((s) => s.name !== COMPLETE_MARKER);
      const mk = b.spans.filter((s) => s.name === COMPLETE_MARKER);
      if (normal.length) main.push({ ...b, spans: normal });
      if (mk.length) markers.push({ ...b, spans: mk });
    }
    for (const traceId of traceIds) {
      if (markers.some((b) => b.spans.some((s) => s.traceId === traceId))) continue;
      const m = this.synthesizeMarker(traceId, main);
      if (m) markers.push(m);
    }
    const spanCount = main.reduce((n, b) => n + b.spans.length, 0);
    return { batches: main, hits, markers, spanCount };
  }

  /** A completion marker for a run whose SDK never sent one (e.g. interrupted). */
  private synthesizeMarker(traceId: string, batches: ResourceSpansBatch[]): ResourceSpansBatch | undefined {
    const run = this.roots.store.getRun(traceId);
    if (!run?.root_span_id) return undefined;
    const rootBatch = batches.find((b) => b.spans.some((s) => s.spanId === run.root_span_id));
    if (!rootBatch) return undefined;
    const root = rootBatch.spans.find((s) => s.spanId === run.root_span_id)!;
    const span: OtlpSpan = {
      traceId,
      spanId: crypto.randomBytes(8).toString("hex"),
      parentSpanId: root.spanId,
      name: COMPLETE_MARKER,
      kind: 1,
      startTimeUnixNano: root.endTimeUnixNano,
      endTimeUnixNano: root.endTimeUnixNano,
      attributes: [
        { key: COMPLETE_MARKER, value: { boolValue: true } },
        { key: "neatlogs.internal", value: { boolValue: true } },
        { key: "neatlogs.span.kind", value: { stringValue: "Neatlogs.INTERNAL" } },
        { key: "neatroots.synthesized", value: { boolValue: true } },
      ],
      events: [],
      links: [],
      status: { code: 0 },
    };
    return { resource: rootBatch.resource, scope: { name: "neatlogs.internal", attributes: [] }, spans: [span] };
  }

  private attachFindings(batches: ResourceSpansBatch[], traceIds: string[]): ResourceSpansBatch[] {
    const bySpan = new Map<string, { id: string; check: string; title: string; probability: number | null; status: string }[]>();
    const rootExtra = new Map<string, KeyValue[]>();
    for (const traceId of traceIds) {
      const run = this.roots.store.getRun(traceId);
      const findings = this.roots.store.findingsForTrace(traceId).filter((f) => f.status !== "failed" && f.status !== "dismissed");
      for (const f of findings) {
        for (const sid of f.evidence_span_ids) {
          const list = bySpan.get(`${traceId}:${sid}`) ?? [];
          list.push({ id: f.id, check: f.check_id, title: f.title, probability: f.probability, status: f.status });
          bySpan.set(`${traceId}:${sid}`, list);
        }
      }
      const extra: KeyValue[] = [{ key: "neatroots.findings.count", value: { intValue: String(findings.length) } }];
      const summary = this.roots.store.getSummary(traceId);
      if (summary) extra.push({ key: "neatroots.run.summary", value: { stringValue: summary.text } });
      const exp = this.roots.store.explanationFor("run", traceId);
      if (exp) extra.push({ key: "neatroots.run.explanation", value: { stringValue: exp.cause } });
      if (run?.root_span_id) rootExtra.set(`${traceId}:${run.root_span_id}`, extra);
    }
    return batches.map((b) => ({
      ...b,
      spans: b.spans.map((s) => {
        const key = `${s.traceId}:${s.spanId}`;
        const add: KeyValue[] = [];
        const fs = bySpan.get(key);
        if (fs) {
          add.push({ key: "neatroots.findings", value: { stringValue: JSON.stringify(fs) } });
          add.push({ key: "neatroots.finding.checks", value: plainToAny(fs.map((f) => f.check)) });
        }
        add.push(...(rootExtra.get(key) ?? []));
        if (!add.length) return s;
        return { ...s, attributes: [...s.attributes.filter((a) => !a.key.startsWith("neatroots.")), ...add] };
      }),
    }));
  }

  async preview(traceIds: string[]): Promise<ForwardPreview> {
    const p = this.prepared(traceIds);
    const kinds = new Map<string, { count: number; samples: { where: string; sample: string }[] }>();
    for (const h of p.hits) {
      const k = kinds.get(h.kind) ?? { count: 0, samples: [] };
      k.count++;
      if (k.samples.length < 5) k.samples.push({ where: h.where, sample: h.sample });
      kinds.set(h.kind, k);
    }
    return {
      trace_ids: traceIds,
      span_count: p.spanCount,
      redactions: [...kinds.entries()].map(([kind, v]) => ({ kind, ...v })),
      endpoint: this.endpoint(),
      has_key: !!(await getCloudKey()),
    };
  }

  /** Builds the exact OTLP request bodies a forward would send (used by tests and dry runs). */
  encode(traceIds: string[]): { main: Uint8Array; markers: Uint8Array | null; spanCount: number; redactions: number } {
    const p = this.prepared(traceIds);
    return {
      main: encodeTraceRequest(p.batches),
      markers: p.markers.length ? encodeTraceRequest(p.markers) : null,
      spanCount: p.spanCount,
      redactions: p.hits.length,
    };
  }

  async forward(traceIds: string[], initiatedBy: string, opts: { endpoint?: string; apiKey?: string } = {}): Promise<ForwardRow> {
    const endpoint = (opts.endpoint ?? this.endpoint()).replace(/\/+$/, "");
    const key = opts.apiKey ?? (await getCloudKey());
    const base = { trace_ids: traceIds, endpoint, initiated_by: initiatedBy };
    const unknown = traceIds.filter((id) => !this.roots.store.getRun(id));
    if (unknown.length) {
      return this.roots.store.insertForward({ ...base, status: "error", http_status: null, span_count: 0, bytes: 0, redactions: 0, error: `no run with id ${unknown.join(", ")}` });
    }
    if (!key) {
      return this.roots.store.insertForward({ ...base, status: "error", http_status: null, span_count: 0, bytes: 0, redactions: 0, error: "No Neatlogs Cloud API key. Add one with `neatroots cloud login` or in the app." });
    }
    let enc: ReturnType<Relay["encode"]>;
    try {
      enc = this.encode(traceIds);
    } catch (err) {
      return this.roots.store.insertForward({ ...base, status: "error", http_status: null, span_count: 0, bytes: 0, redactions: 0, error: `encode failed: ${(err as Error).message}` });
    }
    const send = async (body: Uint8Array) => {
      const gz = zlib.gzipSync(body);
      const res = await fetch(`${endpoint}/v1/traces`, {
        method: "POST",
        headers: { "content-type": "application/x-protobuf", "content-encoding": "gzip", "x-api-key": key, "user-agent": `neatroots/${VERSION}` },
        body: gz,
        signal: AbortSignal.timeout(30_000),
      });
      return { res, bytes: gz.length };
    };
    let bytes = 0;
    try {
      const a = await send(enc.main);
      bytes += a.bytes;
      if (!a.res.ok) {
        const text = (await a.res.text().catch(() => "")).slice(0, 300);
        return this.roots.store.insertForward({ ...base, status: "error", http_status: a.res.status, span_count: enc.spanCount, bytes, redactions: enc.redactions, error: `ingest returned HTTP ${a.res.status}${text ? `: ${text}` : ""}` });
      }
      if (enc.markers) {
        const b = await send(enc.markers);
        bytes += b.bytes;
        if (!b.res.ok) {
          return this.roots.store.insertForward({ ...base, status: "error", http_status: b.res.status, span_count: enc.spanCount, bytes, redactions: enc.redactions, error: `completion marker rejected: HTTP ${b.res.status}` });
        }
      }
      return this.roots.store.insertForward({ ...base, status: "ok", http_status: a.res.status, span_count: enc.spanCount, bytes, redactions: enc.redactions, error: null });
    } catch (err) {
      return this.roots.store.insertForward({ ...base, status: "error", http_status: null, span_count: enc.spanCount, bytes, redactions: enc.redactions, error: (err as Error).message });
    }
  }
}
