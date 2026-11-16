"use client";

import "@xyflow/react/dist/style.css";

import {
  Background,
  Controls,
  MarkerType,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import { useMemo } from "react";

import type { Endpoint } from "@/lib/types";

const MAX_ENDPOINT_NODES = 60;
const SOURCE_COLORS: Record<string, string> = {
  root: "#2FB4E0",
  robots: "#8B8B95",
  probe: "#FF8A3D",
  "api-spec": "#B71095",
  crawl: "#33B5FF",
  js: "#FFC53D",
  form: "#33B5FF",
  sitemap: "#90909B",
};

function pathLabel(endpoint: Endpoint): string {
  let path = endpoint.url;
  try {
    const parsed = new URL(endpoint.url);
    path = `${parsed.pathname}${parsed.search}`;
  } catch {
    // keep the raw URL when it cannot be parsed
  }
  return `${endpoint.method} ${path.length > 46 ? `${path.slice(0, 45)}…` : path}`;
}

export function SurfaceGraph({ endpoints, targetUrl }: { endpoints: Endpoint[]; targetUrl: string }) {
  const { nodes, edges, shown, total } = useMemo(() => {
    const total = endpoints.length;
    const bySource = new Map<string, Endpoint[]>();
    for (const endpoint of endpoints) {
      const bucket = bySource.get(endpoint.source) ?? [];
      bucket.push(endpoint);
      bySource.set(endpoint.source, bucket);
    }
    const sources = [...bySource.keys()].sort();
    const perSource = Math.max(4, Math.floor(MAX_ENDPOINT_NODES / Math.max(sources.length, 1)));
    const columns = 2;
    const rowHeight = 40;

    const graphNodes: Node[] = [];
    const graphEdges: Edge[] = [];
    let cursor = 0;
    let shown = 0;

    const host = (() => {
      try {
        return new URL(targetUrl).host;
      } catch {
        return targetUrl;
      }
    })();

    for (const source of sources) {
      const bucket = (bySource.get(source) ?? []).slice(0, perSource);
      const rows = Math.max(Math.ceil(bucket.length / columns), 1);
      const height = rows * rowHeight;
      const hubId = `source:${source}`;
      graphNodes.push({
        id: hubId,
        position: { x: 300, y: cursor + height / 2 - 18 },
        data: { label: `${source} · ${bySource.get(source)?.length ?? 0}` },
        style: {
          background: "#0A2632",
          border: `1px solid ${SOURCE_COLORS[source] ?? "#0078A7"}66`,
          color: SOURCE_COLORS[source] ?? "#2FB4E0",
          borderRadius: 8,
          fontSize: 11,
          fontWeight: 600,
          padding: "6px 12px",
          width: 150,
          textAlign: "center" as const,
          textTransform: "capitalize" as const,
        },
      });
      graphEdges.push({
        id: `edge:root:${source}`,
        source: "root",
        target: hubId,
        type: "smoothstep",
      });
      bucket.forEach((endpoint, index) => {
        const nodeId = `endpoint:${source}:${index}:${endpoint.url}`;
        const state = endpoint.state ?? (endpoint.status_code === null ? "unverified" : "live");
        graphNodes.push({
          id: nodeId,
          position: {
            x: 540 + (index % columns) * 250,
            y: cursor + Math.floor(index / columns) * rowHeight,
          },
          data: { label: pathLabel(endpoint) },
          style: {
            background: state === "live" ? "#121216" : "#0F0F13",
            border: state === "live" ? "1px solid #26262D" : "1px dashed #3A3A44",
            color:
              state === "live"
                ? endpoint.status_code && endpoint.status_code >= 400
                  ? "#90909B"
                  : "#CACAD2"
                : "#7C7C88",
            borderRadius: 6,
            fontFamily: "JetBrains Mono, Consolas, monospace",
            fontSize: 10,
            padding: "5px 10px",
            width: 230,
          },
        });
        graphEdges.push({
          id: `edge:${source}:${index}:${endpoint.url}`,
          source: hubId,
          target: nodeId,
          type: "smoothstep",
        });
        shown += 1;
      });
      cursor += height + 28;
    }

    graphNodes.unshift({
      id: "root",
      position: { x: 0, y: Math.max(cursor / 2 - 22, 0) },
      data: { label: host },
      style: {
        background: "#0078A7",
        border: "1px solid #2FB4E0",
        color: "#F4F4F6",
        borderRadius: 8,
        fontSize: 12,
        fontWeight: 700,
        padding: "8px 14px",
        width: 200,
        textAlign: "center" as const,
      },
    });

    return {
      nodes: graphNodes,
      edges: graphEdges.map((edge) => ({
        ...edge,
        markerEnd: { type: MarkerType.ArrowClosed, color: "#4A4A54", width: 14, height: 14 },
      })),
      shown,
      total,
    };
  }, [endpoints, targetUrl]);

  if (total === 0) {
    return (
      <p className="px-5 py-10 text-center text-[12.5px] text-slate-400">
        No endpoints recorded yet — the graph appears once discovery finds surface.
      </p>
    );
  }

  return (
    <div className="relative h-[430px] w-full bg-[#0D0D11]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        defaultViewport={{ x: 12, y: 12, zoom: 0.85 }}
        minZoom={0.2}
        maxZoom={1.6}
        style={
          {
            "--xy-controls-button-background-color": "#121216",
            "--xy-controls-button-background-color-hover": "#1B1B21",
            "--xy-controls-button-color": "#B2B2BC",
            "--xy-controls-button-color-hover": "#F4F4F6",
            "--xy-controls-button-border-color": "#26262D",
          } as React.CSSProperties
        }
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnScroll
        proOptions={{ hideAttribution: true }}
      >
        <Background color="#26262D" gap={22} size={1} />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>
      {shown < total ? (
        <span className="pointer-events-none absolute left-3 top-3 rounded-full border border-line bg-panel/90 px-2 py-0.5 text-[10.5px] text-slate-400">
          showing {shown} of {total} endpoints
        </span>
      ) : null}
      <span className="pointer-events-none absolute bottom-3 left-3 flex items-center gap-3 rounded-full border border-line bg-panel/90 px-2.5 py-1 text-[10px] text-slate-400">
        <span className="flex items-center gap-1">
          <span className="h-2.5 w-4 rounded-[2px] border border-[#26262D] bg-[#121216]" /> live
        </span>
        <span className="flex items-center gap-1">
          <span className="h-2.5 w-4 rounded-[2px] border border-dashed border-[#3A3A44] bg-[#0F0F13]" />
          unverified
        </span>
      </span>
    </div>
  );
}
