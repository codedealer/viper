/**
 * M7 `status` TUI (contract D7) — ink is the plan's pick; no hand-rolled
 * ANSI. The component renders `StatusData` only: it owns the 5 s refresh
 * loop, the `q`/Ctrl-C quit and `r` re-run-checks keys. Checks run on
 * first load and on `r` — never on the 5 s refresh.
 */
import type React from "react";
import { useCallback, useEffect, useRef, useState } from "react";
import { Box, Text, useApp, useInput } from "ink";
import { formatBytes, type CollectStatusOptions, type StatusData } from "./status.js";

export interface StatusTuiProps {
  /** Collect one snapshot. `opts.runChecks` drives the probe/cert checks. */
  collect: (opts?: CollectStatusOptions) => Promise<StatusData>;
  /** Refresh interval (default 5 s; tests pass a small value). */
  refreshMs?: number;
}

function Panel({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <Box flexDirection="column" borderStyle="round" paddingX={1}>
      <Text bold color="cyan">
        {title}
      </Text>
      {children}
    </Box>
  );
}

export function StatusTui({ collect, refreshMs = 5000 }: StatusTuiProps) {
  const { exit } = useApp();
  const [data, setData] = useState<StatusData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [checking, setChecking] = useState(false);
  const dataRef = useRef<StatusData | null>(null);
  dataRef.current = data;
  const inflight = useRef(false);
  // A manual `r` pressed while a collect is in flight is deferred, not
  // dropped: the flag records that exactly one re-run-checks refresh is owed
  // once the in-flight collect settles. Rapid repeated `r` presses
  // coalesce to this single flag.
  const pendingRefresh = useRef(false);

  const refresh = useCallback(
    async (runChecks: boolean) => {
      // Overlap guard: a slow collect (e.g. a hung probe after `r`) must
      // not stack a second collect on the same connection — skip the tick
      // if one is still in flight.
      if (inflight.current) return;
      inflight.current = true;
      try {
        const prev = dataRef.current ?? undefined;
        const next = await collect({
          runChecks,
          ...(prev !== undefined ? { prev } : {}),
        });
        setData(next);
        setError(null);
      } catch (err) {
        setError(err instanceof Error ? err.message : String(err));
      } finally {
        inflight.current = false;
        // Settle any deferred manual refresh exactly once (coalesced).
        if (pendingRefresh.current) {
          pendingRefresh.current = false;
          void refresh(true).finally(() => setChecking(false));
        }
      }
    },
    // `collect` is stable for the lifetime of the TUI (a closure over the
    // persistent conn); listing it keeps the hook rule-honest while leaving
    // refresh identity stable so the effect below installs the interval
    // exactly once.
    [collect],
  );

  const first = useRef(true);
  useEffect(() => {
    if (!first.current) return;
    first.current = false;
    void refresh(true);
    const timer = setInterval(() => void refresh(false), refreshMs);
    return () => clearInterval(timer);
  }, [refresh, refreshMs]);

  useInput((input, key) => {
    if (input === "q") exit();
    if (key.ctrl && input === "c") exit();
    if (input === "r") {
      if (inflight.current) {
        // Collect in flight: defer instead of dropping. The `checking`
        // indicator stays up until the deferred refresh completes.
        pendingRefresh.current = true;
        setChecking(true);
      } else {
        setChecking(true);
        void refresh(true).finally(() => setChecking(false));
      }
    }
  });

  if (error !== null && data === null) {
    return (
      <Box paddingX={1} paddingY={1}>
        <Text color="red">status: {error}</Text>
      </Box>
    );
  }
  if (data === null) {
    return (
      <Box paddingX={1} paddingY={1}>
        <Text dimColor>collecting…</Text>
      </Box>
    );
  }

  const d = data;
  const h = d.handshake;

  return (
    <Box flexDirection="column">
      <Box>
        <Panel title={`Server — ${d.name}`}>
          <Text>
            <Text dimColor>ip</Text> {d.ip} <Text dimColor>domain</Text> {d.domain}
          </Text>
          <Text>
            <Text dimColor>xray</Text> {d.xrayVersion} <Text dimColor>unit</Text>{" "}
            <Text color={d.unitActive ? "green" : "red"}>{d.unitActive ? "active" : "INACTIVE"}</Text>
            {d.unitUptime !== "" ? <Text dimColor> (since {d.unitUptime})</Text> : null}
          </Text>
        </Panel>
        <Panel title="Host">
          <Text>
            <Text dimColor>uptime</Text> {d.hostUptime || "n/a"}
          </Text>
          <Text>
            <Text dimColor>cpu</Text> {d.cpu}
          </Text>
          <Text>
            <Text dimColor>ram</Text> {d.ram}
          </Text>
          <Text>
            <Text dimColor>disk /</Text> {d.disk}
          </Text>
        </Panel>
        <Panel title="Clients">
          {d.clients.map((c) => (
            <Text key={c.name}>
              <Text bold>{c.name}</Text>{" "}
              <Text dimColor>
                ({c.uuid}) up {formatBytes(c.uplink)} down {formatBytes(c.downlink)}
              </Text>
            </Text>
          ))}
        </Panel>
        <Panel title="Checks">
          <Text>
            <Text dimColor>handshake</Text>{" "}
            {h.ok === null ? (
              <Text dimColor>not run yet (r to run)</Text>
            ) : (
              <Text color={h.ok ? "green" : "red"}>{h.ok ? "OK" : "FAILED"}</Text>
            )}{" "}
            <Text dimColor>{h.detail}</Text>
          </Text>
          <Text>
            <Text dimColor>cert</Text>{" "}
            {d.cert === null ? (
              <Text dimColor>not run yet (r to run)</Text>
            ) : (
              <Text>
                {d.cert.subject} <Text dimColor>issuer</Text> {d.cert.issuer} <Text dimColor>valid to</Text>{" "}
                {d.cert.validTo}
              </Text>
            )}
          </Text>
        </Panel>
        <Panel title="Sub">
          <Text>
            <Text dimColor>path</Text> {d.subPath}
          </Text>
          <Text>
            <Text dimColor>mtime</Text> {d.subMtime}
          </Text>
        </Panel>
      </Box>
      <Box>
        <Text dimColor>{new Date(d.fetchedAt).toISOString()} </Text>
        {error !== null ? <Text color="red"> (last refresh failed: {error})</Text> : null}
        <Text dimColor>{checking ? " re-running checks…" : ""} q quit · r re-run checks</Text>
      </Box>
    </Box>
  );
}
