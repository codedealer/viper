/**
 * Step runner (M3) — Meridian's step-pipeline model, ported.
 *
 *  - Steps execute sequentially; stop on the first failure (later steps
 *    are unrun and reported as such).
 *  - Per-step trace: `✓ name (detail)` / `– name (skipped: detail)` /
 *    `✗ name (detail)`. ok/changed/skipped lines go to stdout; the
 *    failure line goes to stderr (errors to stderr).
 *  - A step that throws is reported as `failed` with the error message —
 *    the runner itself never crashes on a step exception.
 *
 * Steps take `conn` as a parameter typed by the minimal `SshConn`
 * interface, so unit tests run against a fake conn (M4+ steps).
 */
import type { SshConn } from "../ssh.js";
import type { ServerConfig } from "../config.js";
import type { State } from "../state.js";

export type StepStatus = "ok" | "changed" | "skipped" | "failed";

export interface StepResult {
  status: StepStatus;
  detail?: string;
}

export interface Step {
  name: string;
  run(conn: SshConn, ctx: StepCtx): Promise<StepResult> | StepResult;
}

/**
 * Context carried through the pipeline — exactly the plan's list:
 * server name, ip, validated config, validated state, and rendered
 * artifact name → local path.
 */
export interface StepCtx {
  name: string;
  ip: string;
  config: ServerConfig;
  state: State;
  /** Rendered artifact name (e.g. "config.json") → local path. */
  artifacts: Record<string, string>;
}

export interface RunStepsOptions {
  /** Suppress the console trace (non-interactive use). */
  quiet?: boolean;
}

export interface StepTrace {
  name: string;
  status: StepStatus;
  detail?: string;
}

export interface RunStepsReport {
  /** One entry per step that actually ran, in order. */
  results: StepTrace[];
  /** True if a step failed (and the pipeline stopped). */
  failed: boolean;
  /** Names of steps that did not run because an earlier step failed. */
  unrun: string[];
}

export async function runSteps(
  steps: Step[],
  conn: SshConn,
  ctx: StepCtx,
  opts: RunStepsOptions = {},
): Promise<RunStepsReport> {
  const results: StepTrace[] = [];

  for (let i = 0; i < steps.length; i++) {
    const step = steps[i] as Step;
    let result: StepResult;
    try {
      result = await step.run(conn, ctx);
    } catch (err) {
      result = { status: "failed", detail: err instanceof Error ? err.message : String(err) };
    }

    const trace: StepTrace = { name: step.name, status: result.status };
    if (result.detail !== undefined) trace.detail = result.detail;
    results.push(trace);

    if (!opts.quiet) {
      const detail = trace.detail !== undefined ? ` (${trace.detail})` : "";
      if (result.status === "failed") {
        console.error(`✗ ${step.name}${detail}`);
      } else if (result.status === "skipped") {
        console.log(
          trace.detail !== undefined
            ? `– ${step.name} (skipped: ${trace.detail})`
            : `– ${step.name} (skipped)`,
        );
      } else {
        console.log(`✓ ${step.name}${detail}`);
      }
    }

    if (result.status === "failed") {
      const unrun = steps.slice(i + 1).map((s) => s.name);
      return { results, failed: true, unrun };
    }
  }

  return { results, failed: false, unrun: [] };
}