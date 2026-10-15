import type { RuleCheck } from "./types.js";
import { finalOutput, selectSpans, type SpanInfo, type TraceSnapshot } from "../engine/trace.js";
import { preview } from "../semantics/view.js";

export interface RuleHit {
  /** Whether the condition holds now, looking at the latest spans. */
  firing: boolean;
  evidenceSpanIds: string[];
  params: Record<string, string>;
  title?: string;
}

function keyOf(s: SpanInfo, fields: string[]): string {
  return fields
    .map((f) => {
      if (f === "tool") return s.toolName ?? s.name;
      if (f === "name") return s.name;
      if (f === "input") return JSON.stringify(s.input ?? null);
      if (f === "output") return JSON.stringify(s.output ?? null);
      if (f === "status") return s.status;
      return "";
    })
    .join("\u0000");
}

/** Words an agent uses when it tells the user something went wrong. */
const ADMITS_FAILURE = /\b(fail(ed|s|ure|ing)?|errors?|unable|couldn'?t|could not|can'?t|cannot|unfortunately|sorry|apologi[sz]e|didn'?t (go through|work|succeed)|not (able|successful|completed)|try again|retry)\b/i;

/** "No errors", "without any failures", "no need to try again": the answer says nothing failed. */
const DENIES_FAILURE = /\b(?:no|zero|without(?: any)?|free of)\s+(?:\w+\s+)?(?:errors?|fail(?:ures?|ed)?|issues?|problems?)\b|\bno need to (?:try again|retry)\b/gi;

function clip(s: string, n = 120): string {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

/**
 * Evaluates one rule against a trace. Returns null when the rule has never held in this
 * trace; otherwise `firing` says whether it still holds for the newest spans, which is how
 * a finding later resolves.
 */
export function evaluateRule(check: RuleCheck, t: TraceSnapshot, atEnd: boolean): RuleHit | null {
  const r = check.rule;
  switch (r.type) {
    case "repeat": {
      const spans = selectSpans(t.spans, r.span).sort((a, b) => a.endMs - b.endMs);
      if (spans.length < r.at_least) return null;
      const groups = new Map<string, SpanInfo[]>();
      for (const s of spans) {
        const k = keyOf(s, r.same);
        const g = groups.get(k) ?? [];
        g.push(s);
        groups.set(k, g);
      }
      let worst: SpanInfo[] | undefined;
      for (const g of groups.values()) if (g.length >= r.at_least && (!worst || g.length > worst.length)) worst = g;
      if (!worst) return null;
      const last = spans[spans.length - 1];
      const lastGroup = groups.get(keyOf(last, r.same))!;
      const firing = lastGroup.length >= r.at_least;
      const g = firing ? lastGroup : worst;
      const s0 = g[0];
      return {
        firing,
        evidenceSpanIds: g.map((s) => s.id),
        params: {
          tool: s0.toolName ?? s0.name,
          count: String(g.length),
          args: clip(preview(s0.input, 200)),
          result: clip(g[g.length - 1].error ?? preview(g[g.length - 1].output, 200)),
        },
      };
    }
    case "errors": {
      const spans = selectSpans(t.spans, r.span).sort((a, b) => a.endMs - b.endMs);
      let best: SpanInfo[] = [];
      let cur: SpanInfo[] = [];
      for (const s of spans) {
        if (s.status === "error") {
          cur.push(s);
          if (cur.length > best.length) best = [...cur];
        } else cur = [];
      }
      if (best.length < r.consecutive) return null;
      const firing = cur.length >= r.consecutive;
      const g = firing ? cur : best;
      const last = g[g.length - 1];
      return {
        firing,
        evidenceSpanIds: g.map((s) => s.id),
        params: { tool: last.toolName ?? last.name, error: clip(last.error ?? "error", 200), count: String(g.length) },
      };
    }
    case "count": {
      const spans = selectSpans(t.spans, r.span);
      if (spans.length < r.at_least) return null;
      return { firing: true, evidenceSpanIds: spans.slice(-5).map((s) => s.id), params: { count: String(spans.length) } };
    }
    case "threshold": {
      const run = t.run;
      if (!run) return null;
      const value =
        r.metric === "duration_ms"
          ? (run.ended_ms ?? run.last_span_ms ?? 0) - (run.started_ms ?? 0)
          : r.metric === "span_count"
            ? run.span_count
            : Number(run[r.metric] ?? 0);
      if (value < r.at_least) return null;
      return { firing: true, evidenceSpanIds: [], params: { value: String(Math.round(value)), metric: r.metric } };
    }
    case "match": {
      let re: RegExp;
      try {
        re = new RegExp(r.pattern, r.flags ?? "i");
      } catch {
        return null;
      }
      const hits = selectSpans(t.spans, r.span).filter((s) => {
        const v = r.field === "input" ? s.input : r.field === "output" ? s.output : r.field === "error" ? s.error : s.name;
        if (v === undefined || v === null) return false;
        return re.test(typeof v === "string" ? v : JSON.stringify(v));
      });
      if (!hits.length) return null;
      return { firing: true, evidenceSpanIds: hits.map((s) => s.id), params: { count: String(hits.length), span: hits[0].ref } };
    }
    case "requires_before": {
      const guarded = selectSpans(t.spans, r.span).sort((a, b) => a.startMs - b.startMs || a.seq - b.seq);
      if (!guarded.length) return null;
      // Instrumented spans that succeed usually report status unset, so only errors are ruled out.
      const needed = selectSpans(t.spans, { ...r.requires, status: "any" }).filter((s) => s.status !== "error");
      const missed = guarded.filter((g) => !needed.some((n) => n.id !== g.id && n.startMs <= g.startMs));
      if (!missed.length) return null;
      const first = missed[0];
      return {
        firing: true,
        evidenceSpanIds: missed.map((s) => s.id),
        params: {
          tool: first.toolName ?? first.name,
          requires: String(r.requires.tool ?? r.requires.name ?? r.requires.type ?? "the required step"),
          count: String(missed.length),
        },
      };
    }
    case "unrecovered_error": {
      // Only meaningful once the run is over: until then the agent may still retry.
      if (!atEnd || !t.run) return null;
      // A run that failed or was cut short is already reported by run-failed.
      if (t.run.status === "error" || t.run.interrupted) return null;
      const out = finalOutput(t);
      if (!out || /^("?\s*"?|null|\{\}|\[\])$/.test(out.trim())) return null;
      // An answer that says something failed is the agent being honest, not a problem.
      if (ADMITS_FAILURE.test(out.replace(DENIES_FAILURE, " "))) return null;
      const spans = selectSpans(t.spans, r.span ?? { type: ["tool", "mcp_tool"] }).sort((a, b) => a.endMs - b.endMs || a.seq - b.seq);
      // The last call of each tool decides it: a later success means the agent recovered.
      const last = new Map<string, SpanInfo>();
      for (const s of spans) last.set(s.toolName ?? s.name, s);
      const failed = [...last.values()].filter((s) => s.status === "error");
      if (!failed.length) return null;
      const first = failed[0];
      return {
        firing: true,
        evidenceSpanIds: failed.map((s) => s.id),
        params: {
          tool: first.toolName ?? first.name,
          // Only worth showing when more than one tool stayed failed.
          ...(failed.length > 1 ? { tools: failed.map((s) => s.toolName ?? s.name).join(", "), count: String(failed.length) } : {}),
          error: clip(first.error ?? "error", 200),
        },
      };
    }
    case "run_end": {
      if (!atEnd || !t.run) return null;
      const root = t.spans.find((s) => !s.parentId);
      if (r.when === "error" && t.run.status === "error") {
        return { firing: true, evidenceSpanIds: root ? [root.id] : [], params: { error: clip(root?.error ?? "error", 200) } };
      }
      if (r.when === "interrupted" && t.run.interrupted) {
        return { firing: true, evidenceSpanIds: root ? [root.id] : [], params: { reason: t.run.termination_reason ?? "interrupted" } };
      }
      if (r.when === "no_output" && root) {
        const out = finalOutput(t);
        const empty = !out || /^("?\s*"?|null|\{\}|\[\])$/.test(out.trim());
        if (empty && t.run.status !== "error") return { firing: true, evidenceSpanIds: [root.id], params: {} };
      }
      return null;
    }
  }
}

/** Fills {placeholders} from a finding's params; unknown placeholders are removed. */
export function fillTemplate(template: string, params: Record<string, string>): string {
  // Values go in through private-use markers so the empty-"()" cleanup below only touches
  // the template's own text: "({args})" with no args drops the parens, but an args value
  // like "print()" keeps its own.
  const values: string[] = [];
  return template
    // [[optional text with {param}]] stays only when every placeholder in it has a value.
    .replace(/\[\[([^\]]*)\]\]/g, (_, seg: string) => ([...seg.matchAll(/\{(\w+)\}/g)].every((m) => params[m[1]]?.trim()) ? seg : ""))
    .replace(/\{(\w+)\}/g, (_, k: string) => {
      const v = params[k] !== undefined ? params[k] : "";
      if (!v.trim()) return v;
      values.push(v);
      return `\uE000${values.length - 1}\uE001`;
    })
    .replace(/\(\s*\)/g, "")
    .replace(/\uE000(\d+)\uE001/g, (m, i: string) => values[Number(i)] ?? m)
    .replace(/\s+/g, " ")
    .trim();
}
