/**
 * M7 `rotate` — pure state mutation (contract D5). No SSH here: the
 * caller persists the result BEFORE connecting, renders, and runs the
 * `update` pipeline.
 *
 * Regenerated (the old subscription MUST die):
 *  - Reality x25519 keypair (new pbk/spk),
 *  - a fresh UUIDv4 for EVERY client,
 *  - `subHash` (new sub path — the old sub URL 404s).
 *
 * Preserved:
 *  - `hostKey` (server identity — rotation is not a re-provision),
 *  - `installedPackages` (teardown bookkeeping),
 *  - `shortId` (state-pinned value; the config-pin behavior of
 *    `shortIdOf` is untouched).
 */
import {
  generateRealityKeypair,
  generateSubHash,
  generateUuid,
} from "./keys.js";
import type { State } from "./state.js";

export function rotateState(state: State): State {
  return {
    reality: generateRealityKeypair(),
    shortId: state.shortId,
    subHash: generateSubHash(),
    clients: state.clients.map((c) => ({ name: c.name, uuid: generateUuid() })),
    hostKey: state.hostKey,
    installedPackages: [...state.installedPackages],
  };
}