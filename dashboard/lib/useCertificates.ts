"use client";

import { useCallback, useEffect, useState } from "react";
import { api, loadSampleCertificates, summarize } from "./api";
import type { Certificate, CertificateSummary, Decision, VerifyResult } from "./types";
import { useMode, type Mode } from "@/components/ModeProvider";

type Load<T> = { status: "loading" } | { status: "error"; error: string } | { status: "ready"; data: T };

function message(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

async function fetchList(mode: Mode): Promise<CertificateSummary[]> {
  if (mode === "live") return api.listCertificates();
  return (await loadSampleCertificates()).map(summarize).sort((a, b) => b.timestamp.localeCompare(a.timestamp));
}

export interface CertificateDetail {
  cert: Certificate;
  verify: VerifyResult | null; // null in demo mode: no secret in the browser
  decisions: Decision[];
}

async function fetchDetail(mode: Mode, planId: string): Promise<CertificateDetail> {
  if (mode === "live") {
    const [cert, verify, decisions] = await Promise.all([
      api.getCertificate(planId), api.verify(planId), api.decisions(planId),
    ]);
    return { cert, verify, decisions };
  }
  const cert = (await loadSampleCertificates()).find((c) => c.plan_id === planId);
  if (!cert) throw new Error(`No sample certificate with plan id ${planId}`);
  return { cert, verify: null, decisions: [] };
}

/** Runs `fetcher` whenever mode or the reload counter changes; state is only set from the async result. */
function useLoad<T>(fetcher: (mode: Mode) => Promise<T>, key: string) {
  const { mode } = useMode();
  const [state, setState] = useState<Load<T>>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (mode === "checking") return;
    let alive = true;
    fetcher(mode).then(
      (data) => alive && setState({ status: "ready", data }),
      (err) => alive && setState({ status: "error", error: message(err) }),
    );
    return () => {
      alive = false;
    };
    // fetcher is identified by `key`; re-run on mode, key or explicit reload
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, key, attempt]);

  const reload = useCallback(() => {
    setState({ status: "loading" });
    setAttempt((n) => n + 1);
  }, []);

  return { state, setState, reload, mode };
}

export function useCertificateList() {
  return useLoad(fetchList, "list");
}

export function useCertificate(planId: string) {
  return useLoad((mode) => fetchDetail(mode, planId), `detail:${planId}`);
}
