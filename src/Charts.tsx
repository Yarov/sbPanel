import {
  ResponsiveContainer, PieChart, Pie, Cell, Tooltip,
  BarChart, Bar, XAxis, YAxis, LabelList,
} from "recharts";

const RED = "#ec111a";
export const SEV_COLORS: Record<string, string> = {
  Critical: "#ec111a", High: "#fbbf24", Medium: "#60a5fa", Low: "#6b7280",
  critical: "#ec111a", high: "#fbbf24", medium: "#60a5fa", low: "#6b7280",
};
const PALETTE = ["#ec111a", "#ff5c63", "#fbbf24", "#60a5fa", "#34d399", "#a78bfa", "#f472b6", "#22d3ee"];

const tooltipStyle = {
  background: "#1e1e23", border: "1px solid #2b2b32",
  borderRadius: 8, color: "#f4f4f5", fontSize: 12,
};

export type Datum = { label: string; value: number };

export function Donut({ data }: { data: Datum[] }) {
  const total = data.reduce((a, d) => a + d.value, 0);
  return (
    <ResponsiveContainer width="100%" height={220}>
      <PieChart>
        <Pie data={data} dataKey="value" nameKey="label" cx="50%" cy="50%"
          innerRadius={55} outerRadius={85} paddingAngle={2} stroke="none">
          {data.map((d, i) => (
            <Cell key={i} fill={SEV_COLORS[d.label] ?? PALETTE[i % PALETTE.length]} />
          ))}
        </Pie>
        <Tooltip contentStyle={tooltipStyle} />
        <text x="50%" y="47%" textAnchor="middle" fill="#f4f4f5" fontSize={26} fontWeight={800}>{total}</text>
        <text x="50%" y="57%" textAnchor="middle" fill="#8a8a93" fontSize={11}>abiertos</text>
      </PieChart>
    </ResponsiveContainer>
  );
}

export function BarsH({ data, color = RED }: { data: Datum[]; color?: string }) {
  const h = Math.max(150, data.length * 34 + 10);
  return (
    <ResponsiveContainer width="100%" height={h}>
      <BarChart data={data} layout="vertical" margin={{ left: 6, right: 30, top: 4, bottom: 4 }}>
        <XAxis type="number" hide />
        <YAxis type="category" dataKey="label" width={150}
          tick={{ fill: "#9ca3af", fontSize: 11 }} tickLine={false} axisLine={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgba(255,255,255,0.04)" }} />
        <Bar dataKey="value" fill={color} radius={[0, 5, 5, 0]} barSize={18}>
          <LabelList dataKey="value" position="right" fill="#9ca3af" fontSize={11} />
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}
