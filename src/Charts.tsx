import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend,
  BarChart, Bar, XAxis, YAxis, LabelList,
} from "recharts";

const RED = "#ec111a";
export const SEV_COLORS: Record<string, string> = {
  Critical: "#ec111a", High: "#fbbf24", Medium: "#60a5fa", Low: "#6b7280",
  critical: "#ec111a", high: "#fbbf24", medium: "#60a5fa", low: "#6b7280",
};
// KRI: verde en tiempo, ámbar fuera de SLA, rojo urgente
export const KRI_COLORS: Record<string, string> = {
  IN_TIME: "#34d399",
  NOT_REMEDIATED_IN_SLA: "#fbbf24",
  URGENT_ATTENTION: "#ec111a",
};
const PALETTE = ["#ec111a", "#ff5c63", "#fbbf24", "#60a5fa", "#34d399", "#a78bfa", "#f472b6", "#22d3ee"];
const SEVS = ["Critical", "High", "Medium", "Low"] as const;

const tooltipStyle = {
  background: "#1e1e23", border: "1px solid #2b2b32",
  borderRadius: 8, color: "#f4f4f5", fontSize: 12,
};

export type Datum = { label: string; value: number };
export type StackDatum = Datum & { Critical: number; High: number; Medium: number; Low: number };
type Sel = { onSelect?: (label: string) => void };

// Nombres largos ("Centro Integral de Soluciones - CIS por ScotiaCIS (Portal)")
// no caben en el eje; el tooltip muestra el completo.
const corta = (s: string, n = 22) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

export function Donut({ data, unit = "abiertos", colors, onSelect }: {
  data: Datum[]; unit?: string; colors?: Record<string, string>;
} & Sel) {
  const total = data.reduce((a, d) => a + d.value, 0);
  const paleta = colors ?? SEV_COLORS;
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="label" cx="50%" cy="50%"
          innerRadius={55} outerRadius={85} paddingAngle={2} stroke="none">
          {data.map((d, i) => (
            <Cell key={i} fill={paleta[d.label] ?? PALETTE[i % PALETTE.length]}
              cursor={onSelect ? "pointer" : "default"} onClick={() => onSelect?.(d.label)} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
        <text x="50%" y="47%" textAnchor="middle" fill="#f4f4f5" fontSize={26} fontWeight={800}>
          {total.toLocaleString()}
        </text>
        <text x="50%" y="57%" textAnchor="middle" fill="#8a8a93" fontSize={11}>{unit}</text>
      </PieChart>
    </ResponsiveContainer>
  );
}

/**
 * Barras apiladas por severidad. El total solo no dice nada: un VP con 200 Low
 * y otro con 200 Critical se ven idénticos en una barra simple.
 */
export function StackH({ data, onSelect }: { data: StackDatum[] } & Sel) {
  const h = Math.max(170, data.length * 32 + 40);
  const full = new Map(data.map((d) => [corta(d.label), d.label]));
  const chart = data.map((d) => ({ ...d, label: corta(d.label) }));
  const pick = (l?: string) => l && onSelect?.(full.get(l) ?? l);
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={chart} layout="vertical" margin={{ left: 6, right: 34, top: 4, bottom: 4 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="label" width={150}
          tick={{ fill: "#9ca3af", fontSize: 11 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }}
          labelFormatter={(l) => full.get(String(l)) ?? String(l)} />
        <Legend wrapperStyle={{ fontSize: 11, paddingTop: 4 }} iconSize={9} />
        {SEVS.map((s, i) => (
          <Bar key={s} dataKey={s} stackId="sev" fill={SEV_COLORS[s]} barSize={18}
            radius={i === SEVS.length - 1 ? [0, 5, 5, 0] : undefined}
            cursor={onSelect ? "pointer" : "default"}
            onClick={(e: any) => pick(e?.label ?? e?.payload?.label)}>
            {i === SEVS.length - 1 && (
              <LabelList dataKey="value" position="right" fill="#9ca3af" fontSize={11} />
            )}
          </Bar>
        ))}
      </BarChart>
    </ResponsiveContainer>
  );
}

/** Antigüedad: barras verticales, el rojo sube con la edad. */
export function Aging({ data, onSelect }: { data: Datum[] } & Sel) {
  const tono = ["#34d399", "#60a5fa", "#fbbf24", "#ff5c63", "#ec111a"];
  return (
    <ResponsiveContainer width="100%" height={200}>
      <BarChart data={data} margin={{ left: 0, right: 8, top: 16, bottom: 4 }}>
        <XAxis dataKey="label" tick={{ fill: "#9ca3af", fontSize: 11 }} tickLine={false} axisLine={false} />
        <YAxis hide />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
        <Bar dataKey="value" radius={[5, 5, 0, 0]} barSize={38}
          cursor={onSelect ? "pointer" : "default"}
          onClick={(e: any) => onSelect?.(e?.label ?? e?.payload?.label)}>
          {data.map((_, i) => <Cell key={i} fill={tono[i] ?? RED} />)}
          <LabelList dataKey="value" position="top" fill="#9ca3af" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
