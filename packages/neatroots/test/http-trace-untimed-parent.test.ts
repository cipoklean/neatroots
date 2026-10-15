import { describe, expect, it } from "vitest";
import { httpTraceToBatches } from "../src/ingest/http-trace.js";

const ms = (ns: string) => Number(BigInt(ns) / 1_000_000n);
const times = (body: unknown) =>
  Object.fromEntries(
    httpTraceToBatches(body).batches[0].spans.map((sp) => [sp.name, { start: ms(sp.startTimeUnixNano), end: ms(sp.endTimeUnixNano) }]),
  );

const t0 = Date.parse("2026-10-14T09:00:00.000Z");

// /v1/trace: a parent with no times spans its children, so a trace whose steps carry their own
// timestamps doesn't have to repeat them on the root.
describe("/v1/trace parent without its own times", () => {
  it("starts with its earliest child instead of at ingest time", () => {
    const t = times({
      name: "agent",
      children: [
        { name: "llm", model: "gpt-4o", start: "2026-10-14T09:00:00.000Z", end: "2026-10-14T09:00:02.000Z" },
        { name: "search", tool_name: "search", start: "2026-10-14T09:00:02.000Z", end: "2026-10-14T09:00:05.000Z" },
      ],
    });
    expect(t.agent).toEqual({ start: t0, end: t0 + 5000 });
  });

  it("leaves an untimed step inside a timed parent on its parent's start, as documented", () => {
    const t = times({
      name: "agent",
      start: "2026-10-14T09:00:00.000Z",
      end: "2026-10-14T09:00:09.000Z",
      children: [{ name: "plan", children: [{ name: "llm", model: "gpt-4o", start: "2026-10-14T09:00:03.000Z", end: "2026-10-14T09:00:05.000Z" }] }],
    });
    expect(t.agent).toEqual({ start: t0, end: t0 + 9000 });
    expect(t.plan).toEqual({ start: t0, end: t0 + 5000 });
  });

  it("derives its end from duration_ms after taking its children's start", () => {
    const t = times({
      name: "agent",
      duration_ms: 6000,
      children: [{ name: "llm", model: "gpt-4o", start: "2026-10-14T09:00:01.000Z", end: "2026-10-14T09:00:03.000Z" }],
    });
    expect(t.agent).toEqual({ start: t0 + 1000, end: t0 + 7000 });
  });

  it("keeps a parent's own start, and duration-only traces, as before", () => {
    const own = times({
      name: "agent",
      start: "2026-10-14T09:00:00.000Z",
      children: [{ name: "llm", model: "gpt-4o", start: "2026-10-14T09:00:04.000Z", end: "2026-10-14T09:00:06.000Z" }],
    });
    expect(own.agent).toEqual({ start: t0, end: t0 + 6000 });

    const before = Date.now();
    const dur = times({ name: "agent", children: [{ name: "a", duration_ms: 1000 }, { name: "b", duration_ms: 2000 }] });
    // Span times are stored as Number(ns), good to about 1 µs, so allow 1 ms of rounding.
    expect(dur.agent.start).toBeGreaterThanOrEqual(before - 1);
    expect(dur.agent.end - dur.agent.start).toBe(3000);
    expect(dur.b.start).toBe(dur.a.end);
  });
});
