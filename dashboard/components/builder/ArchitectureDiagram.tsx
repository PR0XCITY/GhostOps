"use client";

import { useMemo } from "react";
import {
  Background, BackgroundVariant, Controls, MarkerType, ReactFlow, Handle, Position,
  type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { ArchitectureServiceInfo, GraphEdge } from "@/lib/types";
import { stripIndex } from "@/lib/builder";

const COLS = 3;
const COL_W = 300;
const NODE_W = 250;

type ServiceNodeData = { service: ArchitectureServiceInfo; label: string; risky: Set<string> };

function ServiceNode({ data }: NodeProps<Node<ServiceNodeData>>) {
  const { service, label, risky } = data;
  const resources = service.resources ?? [];
  const hot = resources.some((r) => risky.has(r));
  return (
    <div className={`rounded-md border px-3 py-2 ${hot ? "border-red-500/70 bg-red-950/60" : "border-line-strong bg-raised"}`}
         style={{ width: NODE_W }}>
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-zinc-600" />
      <div className={`font-mono text-[10px] ${hot ? "text-red-300/80" : "text-zinc-500"}`}>{label}</div>
      <div className={`truncate font-mono text-sm ${hot ? "text-red-100" : "text-zinc-100"}`} translate="no">{service.name}</div>
      <ul className="mt-1.5 flex flex-col gap-0.5">
        {resources.filter((r) => !r.startsWith("data.")).map((r) => (
          <li key={r} className={`truncate font-mono text-[10px] ${risky.has(r) ? "text-red-300" : "text-zinc-400"}`} title={r}>
            {risky.has(r) ? "! " : ""}{r.split(".")[0].replace(/^aws_/, "")}
          </li>
        ))}
      </ul>
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-zinc-600" />
    </div>
  );
}

const nodeTypes = { service: ServiceNode };

export function ArchitectureDiagram({ services, labels, riskyResources, edges }: {
  services: ArchitectureServiceInfo[];
  labels: Record<string, string>;
  riskyResources: Set<string>; // resource addresses without [index]
  edges: GraphEdge[];           // resource-level references from the last check
}) {
  const { rfNodes, rfEdges } = useMemo(() => {
    const rowHeights: number[] = [];
    services.forEach((s, i) => {
      const row = Math.floor(i / COLS);
      const h = 64 + 15 * (s.resources ?? []).filter((r) => !r.startsWith("data.")).length;
      rowHeights[row] = Math.max(rowHeights[row] ?? 0, h);
    });
    const rowY = rowHeights.reduce<number[]>((acc, _h, i) => [...acc, i === 0 ? 0 : acc[i - 1] + rowHeights[i - 1] + 40], []);
    const rfNodes: Node<ServiceNodeData>[] = services.map((s, i) => ({
      id: s.name,
      type: "service",
      position: { x: (i % COLS) * COL_W, y: rowY[Math.floor(i / COLS)] },
      data: { service: s, label: labels[s.type] ?? s.type, risky: riskyResources },
    }));
    // service-level edges: a resource of one service referencing a resource of another
    const owner = new Map<string, string>();
    services.forEach((s) => (s.resources ?? []).forEach((r) => owner.set(r, s.name)));
    const pairs = new Set<string>();
    for (const e of edges) {
      const a = owner.get(stripIndex(e.source));
      const b = owner.get(stripIndex(e.target));
      if (a && b && a !== b) pairs.add(`${a}|${b}`);
    }
    const rfEdges: Edge[] = [...pairs].map((p) => {
      const [source, target] = p.split("|");
      return { id: p, source, target, markerEnd: { type: MarkerType.ArrowClosed, color: "#71717a" },
               style: { stroke: "#71717a" } };
    });
    return { rfNodes, rfEdges };
  }, [services, labels, riskyResources, edges]);

  if (!services.length) {
    return <p className="px-4 py-10 text-sm text-zinc-500">The diagram appears when you add a service.</p>;
  }
  return (
    <div className="h-[340px] w-full" role="img"
         aria-label={`Architecture diagram: ${services.length} services, ${riskyResources.size} flagged resources.`}>
      <ReactFlow nodes={rfNodes} edges={rfEdges} nodeTypes={nodeTypes} fitView fitViewOptions={{ padding: 0.15, maxZoom: 1 }}
                 minZoom={0.3} maxZoom={2} colorMode="dark" nodesConnectable={false}>
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#27272a" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
