"use client";

import { createContext, useCallback, useContext, useEffect, useState } from "react";
import { apiReachable } from "@/lib/api";

export type Mode = "checking" | "live" | "demo";

interface ModeContextValue {
  mode: Mode;
  recheck: () => Promise<Mode>;
}

const ModeContext = createContext<ModeContextValue>({ mode: "checking", recheck: async () => "checking" });

export function ModeProvider({ children }: { children: React.ReactNode }) {
  const [mode, setMode] = useState<Mode>("checking");

  useEffect(() => {
    let alive = true;
    void apiReachable().then((ok) => {
      if (alive) setMode(ok ? "live" : "demo");
    });
    return () => {
      alive = false;
    };
  }, []);

  const recheck = useCallback(async () => {
    const next: Mode = (await apiReachable()) ? "live" : "demo";
    setMode(next);
    return next;
  }, []);

  return <ModeContext.Provider value={{ mode, recheck }}>{children}</ModeContext.Provider>;
}

export function useMode() {
  return useContext(ModeContext);
}
