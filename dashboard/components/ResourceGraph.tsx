"use client";

import { useMemo } from "react";
import {
  Background, BackgroundVariant, Controls, Handle, MarkerType, Position, ReactFlow,
  type Edge, type Node, type NodeProps,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import type { GraphEdge, GraphNode } from "@/lib/types";
import { resourceType } from "@/lib/format";

// 230px nodes + 170px gap: labels scale with zoom, so the gap must exceed the
// widest label ("vpc_security_group_ids" is about 132px) at any zoom level
const COL_WIDTH = 400;
const ROW_HEIGHT = 96;
const REASON_LABEL: Record<string, string> = {
  public_exposure: "public",
  opens_public_access: "opens access",
  iam_widened: "IAM widened",
  iam_admin: "IAM admin",
};

type ResourceNodeData = { node: GraphNode };

function ResourceNode({ data }: NodeProps<Node<ResourceNodeData>>) {
  const { node } = data;
  const name = node.id.slice(resourceType(node.id).length + 1) || node.id;
  return (
    <div
      className={`w-[230px] rounded-md border px-3 py-2 ${
        node.risk ? "border-red-500/70 bg-red-950/70 shadow-[0_0_0_3px_rgba(239,68,68,0.12)]" : "border-line-strong bg-raised"
      }`}
    >
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-0 !bg-zinc-600" />
      <div className={`truncate font-mono text-[10px] ${node.risk ? "text-red-300/80" : "text-zinc-500"}`}>{node.type}</div>
      <div className={`truncate font-mono text-sm ${node.risk ? "text-red-100" : "text-zinc-100"}`} title={node.id}>
        {name}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-1">
        <span className="rounded bg-white/5 px-1 py-px font-mono text-[10px] text-zinc-400">{node.action}</span>
        {node.risk_reasons.map((r) => (
          <span key={r} className="rounded bg-red-500/20 px-1 py-px font-mono text-[10px] text-red-200">
            {REASON_LABEL[r] ?? r}
          </span>
        ))}
      </div>
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-0 !bg-zinc-600" />
    </div>
  );
}

const nodeTypes = { resource: ResourceNode };

/** Column = longest chain of references leading to the node, so referrers sit left of what they use. */
function layout(nodes: GraphNode[], edges: GraphEdge[]): Map<string, { x: number; y: number }> {
  const incoming = new Map<string, string[]>(nodes.map((n) => [n.id, []]));
  for (const e of edges) incoming.get(e.target)?.push(e.source);
  const depth = new Map<string, number>();
  const visit = (id: string, stack: Set<string>): number => {
    if (depth.has(id)) return depth.get(id)!;
    if (stack.has(id)) return 0; // reference cycle: stop
    stack.add(id);
    const preds = incoming.get(id) ?? [];
    const d = preds.length ? 1 + Math.max(...preds.map((p) => visit(p, stack))) : 0;
    stack.delete(id);
    depth.set(id, d);
    return d;
  };
  nodes.forEach((n) => visit(n.id, new Set()));
  const columns = new Map<number, string[]>();
  for (const n of nodes) {
    const d = depth.get(n.id) ?? 0;
    columns.set(d, [...(columns.get(d) ?? []), n.id]);
  }
  const positions = new Map<string, { x: number; y: number }>();
  for (const [col, ids] of columns) ids.forEach((id, row) => positions.set(id, { x: col * COL_WIDTH, y: row * ROW_HEIGHT }));
  return positions;
}

export function ResourceGraph({ nodes, edges }: { nodes: GraphNode[]; edges: GraphEdge[] }) {
  const { rfNodes, rfEdges } = useMemo(() => {
    const positions = layout(nodes, edges);
    const risky = new Set(nodes.filter((n) => n.risk).map((n) => n.id));
    const rfNodes: Node<ResourceNodeData>[] = nodes.map((n) => ({
      id: n.id, type: "resource", position: positions.get(n.id) ?? { x: 0, y: 0 }, data: { node: n }, draggable: true,
    }));
    const rfEdges: Edge[] = edges.map((e) => {
      const hot = risky.has(e.source) && risky.has(e.target);
      const color = hot ? "#ef4444" : "#52525b";
      // depends_on is ordering only, not a data reference: dashed and unlabelled
      const references = e.via.filter((v) => v !== "depends_on");
      return {
        id: `${e.source}->${e.target}`,
        source: e.source,
        target: e.target,
        label: references.join(", ") || undefined,
        labelStyle: { fill: hot ? "#fca5a5" : "#a1a1aa", fontSize: 10, fontFamily: "var(--font-geist-mono)" },
        labelBgStyle: { fill: "#09090b" },
        style: { stroke: color, strokeWidth: hot ? 2 : 1.25, strokeDasharray: references.length ? undefined : "4 4" },
        markerEnd: { type: MarkerType.ArrowClosed, color, width: 16, height: 16 },
      };
    });
    return { rfNodes, rfEdges };
  }, [nodes, edges]);

  if (nodes.length === 0) {
    return <p className="px-4 py-10 text-sm text-zinc-500">No resources remain after this change.</p>;
  }
  const flagged = nodes.filter((n) => n.risk).length;
  return (
    <div
      className="h-[440px] w-full"
      role="img"
      aria-label={`Resource graph: ${nodes.length} resources, ${edges.length} references, ${flagged} flagged as risky. The same resources are listed under Resource Changes.`}
    >
      <ReactFlow
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.2, maxZoom: 1 }}
        minZoom={0.3}
        maxZoom={2}
        colorMode="dark"
        nodesConnectable={false}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#27272a" />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
