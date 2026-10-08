"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { API_IS_LOCAL, WAKE_TIMEOUT_MS, apiReachable } from "@/lib/api";

export type Mode = "checking" | "live" | "demo";

interface ModeContextValue {
  mode: Mode;
  waking: boolean; // a hosted API did not answer at once: waiting for it to wake up
  recheck: () => Promise<Mode>;
}

const ModeContext = createContext<ModeContextValue>({ mode: "checking", waking: false, recheck: async () => "checking" });

/** Quick check first; a remote API that does not answer gets one long wait (cold start) before demo mode. */
async function detect(onWaking: () => void): Promise<Mode> {
  if (await apiReachable()) return "live";
  if (API_IS_LOCAL) return "demo";
  onWaking();
  return (await apiReachable(WAKE_TIMEOUT_MS)) ? "live" : "demo";
}

export function ModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<Mode>("checking");
  const [waking, setWaking] = useState(false);

  useEffect(() => {
    let alive = true;
    void detect(() => alive && setWaking(true)).then((next) => {
      if (!alive) return;
      setMode(next);
      setWaking(false);
    });
    return () => {
      alive = false;
    };
  }, []);

  const recheck = useCallback(async () => {
    setMode("checking");
    const next = await detect(() => setWaking(true));
    setMode(next);
    setWaking(false);
    return next;
  }, []);

  return <ModeContext.Provider value={{ mode, waking, recheck }}>{children}</ModeContext.Provider>;
}

export function useMode() {
  return useContext(ModeContext);
}
