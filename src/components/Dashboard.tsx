/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { Shield, ShieldAlert, CheckCircle, Search, AlertOctagon, Terminal, Trash2, ChevronRight, FileText, BarChart2 } from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar } from "recharts";
import { DashboardStats, ScanRecord, ThreatLevel, UserRole } from "../types.js";

interface DashboardProps {
  stats: DashboardStats;
  loading: boolean;
  onViewRecord: (record: ScanRecord) => void;
  onDeleteRecord?: (id: string) => void;
  currentUserRole?: UserRole;
}

export function Dashboard({ stats, loading, onViewRecord, onDeleteRecord, currentUserRole }: DashboardProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterType, setFilterType] = useState<"ALL" | "Phishing" | "Legitimate">("ALL");

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center py-20 space-y-4 font-sans">
        <div className="w-12 h-12 border-4 border-cyan-500 border-t-transparent rounded-full animate-spin shadow-[0_0_15px_rgba(6,182,212,0.3)]"></div>
        <p className="font-mono text-xs text-slate-400">Loading terminal analytics grids...</p>
      </div>
    );
  }

  // Filter investigations
  const filteredInvestigations = stats.recentInvestigations.filter(item => {
    const matchesSearch = 
      item.incidentId.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.subject.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.sender.toLowerCase().includes(searchTerm.toLowerCase());
    
    if (filterType === "ALL") return matchesSearch;
    return matchesSearch && item.prediction === filterType;
  });

  // Color mappings for Recharts
  const SEVERITY_COLORS = {
    low: "#06b6d4",       // Cyan
    medium: "#eab308",   // Yellow
    high: "#f97316",     // Orange
    critical: "#f43f5e"   // Rose
  };

  const pieData = [
    { name: "Low Risk", value: stats.threatDistribution?.low || 0, color: SEVERITY_COLORS.low },
    { name: "Medium Risk", value: stats.threatDistribution?.medium || 0, color: SEVERITY_COLORS.medium },
    { name: "High Risk", value: stats.threatDistribution?.high || 0, color: SEVERITY_COLORS.high },
    { name: "Critical Risk", value: stats.threatDistribution?.critical || 0, color: SEVERITY_COLORS.critical }
  ].filter(item => item.value > 0);

  return (
    <div className="space-y-8 font-sans">
      {/* 1. TOP CARDS STATS */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Card: Total Scanned */}
        <div className="bg-[#0b111a] border border-slate-800/80 p-6 rounded-2xl relative overflow-hidden shadow-xl">
          <div className="absolute top-0 right-0 w-16 h-16 bg-cyan-500/5 blur-[20px]"></div>
          <p className="text-[10px] font-mono uppercase text-slate-500 font-bold tracking-widest mb-1.5">Mails Audited</p>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-white font-sans">{stats.totalScanned}</span>
            <span className="text-[10px] text-cyan-400 font-mono">[Total LOGS]</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-3 flex items-center gap-1.5 font-mono">
            <Terminal className="w-3.5 h-3.5 text-cyan-400" /> Active stream status: normal
          </div>
        </div>

        {/* Card: Phishing Detected */}
        <div className="bg-[#0b111a] border border-slate-800/80 p-6 rounded-2xl relative overflow-hidden shadow-xl">
          <div className="absolute top-0 right-0 w-16 h-16 bg-rose-500/5 blur-[20px]"></div>
          <p className="text-[10px] font-mono uppercase text-slate-500 font-bold tracking-widest mb-1.5">Threats Uncovered</p>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-rose-500 font-sans">{stats.totalPhishing}</span>
            <span className="text-[10px] text-rose-450 font-mono">
              ({stats.totalScanned > 0 ? Math.round((stats.totalPhishing / stats.totalScanned) * 100) : 0}%)
            </span>
          </div>
          <div className="text-[10px] text-slate-400 mt-3 flex items-center gap-1.5 font-mono">
            <ShieldAlert className="w-3.5 h-3.5 text-rose-500" /> Malicious payload matches
          </div>
        </div>

        {/* Card: Legitimate verified */}
        <div className="bg-[#0b111a] border border-slate-800/80 p-6 rounded-2xl relative overflow-hidden shadow-xl">
          <div className="absolute top-0 right-0 w-16 h-16 bg-cyan-500/5 blur-[20px]"></div>
          <p className="text-[10px] font-mono uppercase text-slate-500 font-bold tracking-widest mb-1.5">Safe Deliveries Passed</p>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-cyan-400 font-sans">{stats.totalLegitimate}</span>
            <span className="text-[10px] text-cyan-400 font-mono">
              ({stats.totalScanned > 0 ? Math.round((stats.totalLegitimate / stats.totalScanned) * 100) : 0}%)
            </span>
          </div>
          <div className="text-[10px] text-slate-400 mt-3 flex items-center gap-1.5 font-mono">
            <CheckCircle className="w-3.5 h-3.5 text-cyan-400" /> DKIM/SPF identities verified
          </div>
        </div>

        {/* Card: Peak Danger index */}
        <div className="bg-[#0b111a] border border-slate-800/80 p-6 rounded-2xl relative overflow-hidden shadow-xl">
          <div className="absolute top-0 right-0 w-16 h-16 bg-amber-500/5 blur-[20px]"></div>
          <p className="text-[10px] font-mono uppercase text-slate-500 font-bold tracking-widest mb-1.5">Critical Incidents</p>
          <div className="flex items-baseline gap-2">
            <span className="text-3xl font-extrabold text-amber-500 font-sans">
              {stats.threatDistribution?.critical || 0}
            </span>
            <span className="text-[10px] text-amber-400 font-mono">Action req.</span>
          </div>
          <div className="text-[10px] text-slate-400 mt-3 flex items-center gap-1.5 font-mono">
            <AlertOctagon className="w-3.5 h-3.5 text-amber-500" /> High score severity alerts
          </div>
        </div>
      </div>

      {/* 2. SOC CHARTS PANELS COLUMNS */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Trend line graph */}
        <div className="lg:col-span-2 bg-[#0b111a]/45 border border-slate-800/80 p-6 rounded-2xl space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-bold text-slate-200">Activity Vectors Timeline</h3>
              <p className="text-[11px] text-slate-500">Volume tracking representing recent mail threat frequencies</p>
            </div>
            <div className="flex items-center gap-4 text-[10px] font-mono">
              <span className="flex items-center gap-1.5 text-slate-400">
                <span className="w-2.5 h-2.5 bg-cyan-500 rounded-full"></span> Audited
              </span>
              <span className="flex items-center gap-1.5 text-slate-400">
                <span className="w-2.5 h-2.5 bg-rose-500 rounded-full"></span> Phishing
              </span>
            </div>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={stats.monthlyTrends || []} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="scannedGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#06b6d4" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="phishGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#f43f5e" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="#f43f5e" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="month" stroke="#475569" fontSize={9} tickLine={false} />
                <YAxis stroke="#475569" fontSize={9} tickLine={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155", borderRadius: "10px", fontSize: "11px", color: "#f8fafc" }}
                  itemStyle={{ color: "#f8fafc" }}
                />
                <Area type="monotone" dataKey="scanned" stroke="#06b6d4" strokeWidth={2} fillOpacity={1} fill="url(#scannedGrad)" name="Total Audited" />
                <Area type="monotone" dataKey="phishing" stroke="#f43f5e" strokeWidth={2} fillOpacity={1} fill="url(#phishGrad)" name="Malicious Detected" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Pie Distribution chart */}
        <div className="bg-[#0b111a]/45 border border-slate-800/80 p-6 rounded-2xl flex flex-col justify-between">
          <div>
            <h3 className="text-sm font-bold text-slate-200">Incident Severity Breakdowns</h3>
            <p className="text-[11px] text-slate-500">Threat risk scores levels distribution ratios</p>
          </div>

          <div className="h-44 w-full relative flex items-center justify-center my-2">
            {pieData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={pieData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={70}
                    paddingAngle={3}
                    dataKey="value"
                  >
                    {pieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ backgroundColor: "#0f172a", border: "1px solid #334155", borderRadius: "10px", fontSize: "11px", color: "#f8fafc" }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="text-xs text-slate-500 font-mono">No incidents reported.</div>
            )}
            <div className="absolute text-center bg-slate-950/60 p-2.5 rounded-full border border-slate-800/40">
              <span className="text-[10px] text-slate-500 font-mono block">Threat ratio</span>
              <span className="text-xl font-extrabold text-rose-500 font-mono">
                {stats.totalScanned > 0 ? Math.round((stats.totalPhishing / stats.totalScanned) * 100) : 0}%
              </span>
            </div>
          </div>

          <div className="space-y-1.5 text-[10px] text-slate-400 font-mono">
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#06b6d4]"></span> Low</span>
              <span className="text-slate-350">{stats.threatDistribution?.low || 0} scans</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-yellow-500"></span> Medium</span>
              <span className="text-slate-350">{stats.threatDistribution?.medium || 0} scans</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-orange-500"></span> High</span>
              <span className="text-slate-350">{stats.threatDistribution?.high || 0} scans</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-rose-500"></span> Critical</span>
              <span className="text-slate-350">{stats.threatDistribution?.critical || 0} scans</span>
            </div>
          </div>
        </div>
      </div>

      {/* 3. RECENT INVESTIGATIONS GRID LIST */}
      <section className="bg-[#0b111a]/45 border border-slate-800/80 rounded-2xl overflow-hidden shadow-2xl">
        <div className="p-6 border-b border-slate-800/60 flex flex-col md:flex-row items-center justify-between gap-4">
          <div>
            <h3 className="text-sm font-bold text-slate-200">Incident Investigations Database</h3>
            <p className="text-[11px] text-slate-500">Stored scan records and multi-vector threat reports audit pipeline</p>
          </div>

          <div className="flex flex-col sm:flex-row items-stretch gap-3 w-full md:w-auto">
            {/* Search */}
            <div className="relative">
              <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                <Search className="w-4 h-4 text-slate-500" />
              </span>
              <input
                type="text"
                placeholder="Query Incident / IP / Sender..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="w-full sm:w-60 pl-9 pr-4 py-2 bg-slate-950 border border-slate-800 rounded-xl text-xs font-mono placeholder-slate-655 text-slate-300 focus:outline-none focus:border-cyan-500/80 text-left font-medium"
              />
            </div>

            {/* Filter */}
            <div className="flex bg-slate-950 border border-slate-800 p-1 rounded-xl text-xs font-mono">
              <button
                type="button"
                onClick={() => setFilterType("ALL")}
                className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${
                  filterType === "ALL" ? "bg-slate-805 text-cyan-400 font-bold border border-slate-800/60" : "text-slate-400"
                }`}
              >
                ALL
              </button>
              <button
                type="button"
                onClick={() => setFilterType("Phishing")}
                className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${
                  filterType === "Phishing" ? "bg-rose-500/10 text-rose-400 font-bold border border-rose-500/10" : "text-slate-400"
                }`}
              >
                Threats
              </button>
              <button
                type="button"
                onClick={() => setFilterType("Legitimate")}
                className={`px-3 py-1 rounded-lg transition-all cursor-pointer ${
                  filterType === "Legitimate" ? "bg-cyan-500/10 text-cyan-400 font-bold border border-cyan-500/10" : "text-slate-400"
                }`}
              >
                Clean
              </button>
            </div>
          </div>
        </div>

        {/* Table list */}
        <div className="overflow-x-auto w-full">
          <table className="w-full border-collapse text-left text-xs font-mono">
            <thead>
              <tr className="bg-slate-950/60 text-slate-500 border-b border-slate-800/60 uppercase text-[10px] font-bold tracking-wider">
                <th className="py-3 px-6">Incident ID / Date</th>
                <th className="py-3 px-6">Sender Credentials</th>
                <th className="py-3 px-6">Email Subject</th>
                <th className="py-3 px-6">Safety Label</th>
                <th className="py-3 px-6 text-center">Threat Risk Index</th>
                <th className="py-3 px-6 text-center">Action Target</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/40 text-slate-300">
              {filteredInvestigations.length > 0 ? (
                filteredInvestigations.map((scan) => {
                  const isPhish = scan.prediction === "Phishing";
                  const dateStr = new Date(scan.createdAt).toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit"
                  });

                  return (
                    <tr key={scan.id} className="hover:bg-slate-900/30 transition-colors group">
                      <td className="py-4 px-6">
                        <span className="block text-slate-200 font-bold font-sans tracking-wide">{scan.incidentId}</span>
                        <span className="text-[10px] text-slate-500">{dateStr}</span>
                      </td>
                      <td className="py-4 px-6 max-w-[180px] break-all text-slate-350">
                        {scan.sender}
                      </td>
                      <td className="py-4 px-6 max-w-[200px] truncate text-slate-200">
                        {scan.subject}
                      </td>
                      <td className="py-4 px-6">
                        <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[10px] font-bold ${
                          isPhish 
                            ? "bg-rose-500/10 text-rose-450 border border-rose-500/20" 
                            : "bg-cyan-500/10 text-cyan-450 border border-cyan-500/20"
                        }`}>
                          <span className={`w-1.5 h-1.5 rounded-full ${isPhish ? "bg-rose-500 animate-pulse" : "bg-cyan-500"}`}></span>
                          {scan.prediction}
                        </span>
                      </td>
                      <td className="py-4 px-6 text-center">
                        <div className="flex flex-col items-center justify-center font-mono">
                          <span className={`text-sm font-extrabold ${
                            scan.threatScore > 75 
                              ? "text-rose-500" 
                              : scan.threatScore > 40 
                              ? "text-amber-500" 
                              : "text-cyan-400"
                          }`}>
                            {scan.threatScore}%
                          </span>
                          <span className="text-[9px] text-slate-500 uppercase">{scan.threatLevel}</span>
                        </div>
                      </td>
                      <td className="py-4 px-6 text-center">
                        <div className="flex items-center justify-center gap-2">
                          <button
                            type="button"
                            onClick={() => onViewRecord(scan)}
                            className="inline-flex items-center gap-1 bg-slate-950 border border-slate-800 hover:border-cyan-500/35 hover:text-cyan-400 py-1.5 px-3 rounded-lg cursor-pointer transition-all focus:outline-none"
                          >
                            Investigate <ChevronRight className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                          </button>

                          {currentUserRole === UserRole.ADMIN && onDeleteRecord && (
                            <button
                              type="button"
                              onClick={() => onDeleteRecord(scan.id)}
                              className="text-slate-500 hover:text-rose-400 p-1.5 rounded-lg border border-transparent hover:border-rose-500/20 transition-all cursor-pointer focus:outline-none"
                              title="Delete Incident Record"
                            >
                              <Trash2 className="w-4 h-4" />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={6} className="text-center py-12 text-slate-500 font-mono">
                    [SYS_WARN]: No matching digital forensic findings logged in Database archives.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  );
}
