/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { ShieldAlert, Trash2, Mail, Users, Terminal, Shield, RefreshCw, Ban, Unlock, Clock, Globe, Plus, AlertOctagon, Key, ShieldX } from "lucide-react";
import { UserRole, AuditLog, LoginAttempt, BannedIp } from "../types.js";

interface AdminPanelProps {
  currentUserRole?: UserRole;
  token: string;
}

export function AdminPanel({ currentUserRole, token }: AdminPanelProps) {
  const [users, setUsers] = useState<any[]>([]);
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loginAttempts, setLoginAttempts] = useState<LoginAttempt[]>([]);
  const [bannedIps, setBannedIps] = useState<BannedIp[]>([]);
  const [activeTab, setActiveTab] = useState<"logs" | "access">("logs");
  
  const [banIpInput, setBanIpInput] = useState("");
  const [banReasonInput, setBanReasonInput] = useState("");
  
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (currentUserRole === UserRole.ADMIN) {
      fetchAdminData();
    }
  }, [currentUserRole]);

  const fetchAdminData = async () => {
    setLoading(true);
    try {
      // Fetch users
      const usersRes = await fetch("/api/admin/users", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      const usersData = await usersRes.json();
      if (usersRes.ok) {
        setUsers(usersData);
      }

      // Fetch logs
      const logsRes = await fetch("/api/admin/logs", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      const logsData = await logsRes.json();
      if (logsRes.ok) {
        setLogs(logsData);
      }

      // Fetch login attempts
      const attemptsRes = await fetch("/api/admin/login-attempts", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      const attemptsData = await attemptsRes.json();
      if (attemptsRes.ok) {
        setLoginAttempts(attemptsData);
      }

      // Fetch banned IPs
      const bannedRes = await fetch("/api/admin/banned-ips", {
        headers: { "Authorization": `Bearer ${token}` }
      });
      const bannedData = await bannedRes.json();
      if (bannedRes.ok) {
        setBannedIps(bannedData);
      }
    } catch (err) {
      console.error("Failed to load admin logs/users/access-controls:", err);
    } finally {
      setLoading(false);
    }
  };

  const handleBanIp = async (ipToBan: string, reasonText?: string) => {
    setSuccess(null);
    setError(null);
    if (!ipToBan.trim()) {
      setError("Please key in a valid IP Address format.");
      return;
    }
    try {
      const response = await fetch("/api/admin/ban-ip", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ ip: ipToBan, reason: reasonText || banReasonInput })
      });
      const data = await response.json();
      if (response.ok) {
        setSuccess(`IP Address [${ipToBan}] successfully banned.`);
        setBanIpInput("");
        setBanReasonInput("");
        fetchAdminData();
      } else {
        throw new Error(data.error || "IP banning rejected.");
      }
    } catch (err: any) {
      setError(err.message || "Banning attempt failed.");
    }
  };

  const handleUnbanIp = async (ipToUnban: string) => {
    setSuccess(null);
    setError(null);
    try {
      const response = await fetch("/api/admin/unban-ip", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": `Bearer ${token}`
        },
        body: JSON.stringify({ ip: ipToUnban })
      });
      const data = await response.json();
      if (response.ok) {
        setSuccess(`IP Address [${ipToUnban}] ban successfully lifted.`);
        fetchAdminData();
      } else {
        throw new Error(data.error || "IP unbanning rejected.");
      }
    } catch (err: any) {
      setError(err.message || "Unbanning attempt failed.");
    }
  };

  const handleClearLogs = async () => {
    if (!window.confirm("CONFIRMATION REQUIRED: Are you sure you want to permanently purge all security audit trails?")) {
      return;
    }
    setSuccess(null);
    setError(null);
    try {
      const response = await fetch("/api/admin/logs", {
        method: "DELETE",
        headers: { "Authorization": `Bearer ${token}` }
      });
      const data = await response.json();
      if (response.ok) {
        setLogs([]);
        setSuccess("Terminal audit trails purged successfully.");
        dbAddLocalLog("Audit Logs Cleared");
      } else {
        throw new Error(data.error || "Removal rejected by system policy.");
      }
    } catch (err: any) {
      setError(err.message || "Removal sequence failed.");
    }
  };

  const dbAddLocalLog = (action: string) => {
    const mockLog: AuditLog = {
      id: "log_" + Math.random().toString(36).substr(2, 9),
      username: "admin",
      action,
      details: "purged terminal traces",
      ip: "127.0.0.1",
      createdAt: new Date().toISOString()
    };
    setLogs([mockLog]);
  };

  // Guard Clause Security Role Checking
  if (currentUserRole !== UserRole.ADMIN) {
    return (
      <div className="flex flex-col items-center justify-center py-20 px-4 text-center max-w-md mx-auto space-y-6">
        <div className="p-4 bg-rose-500/10 border border-rose-500/20 text-rose-500 rounded-full">
          <ShieldAlert className="w-12 h-12 shrink-0 animate-bounce" />
        </div>
        <div className="space-y-2">
          <h2 className="text-xl font-extrabold text-white tracking-tight font-mono">Access Gated [SYS_DENIED]</h2>
          <p className="text-xs text-slate-500 font-mono leading-relaxed">
            Your terminal identity holds "Security Analyst" clearance. Complete administrative action rights are barred. Switch to admin account to authorize.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-8 font-sans">
      {/* HEADER */}
      <div className="border-b border-slate-800/60 pb-5 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Shield className="w-5.5 h-5.5 text-cyan-400" /> Administrative Terminal Command Control
          </h2>
          <p className="text-xs text-slate-500">Perform credential directory reviews, access login telemetry, and enforce IP blacklist containment</p>
        </div>

        <button
          onClick={fetchAdminData}
          disabled={loading}
          className="self-start sm:self-center inline-flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 py-2 px-4 rounded-xl text-xs font-mono cursor-pointer transition-all focus:outline-none"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} /> Refresh directory
        </button>
      </div>

      {/* ADMIN TABS CONTROLLER */}
      <div className="flex gap-4 border-b border-slate-850">
        <button
          type="button"
          onClick={() => { setActiveTab("logs"); setSuccess(null); setError(null); }}
          className={`pb-3 text-xs uppercase font-mono tracking-wider transition-all border-b-2 cursor-pointer ${
            activeTab === "logs"
              ? "border-cyan-500 text-cyan-400 font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          [01] System Audit & Users
        </button>
        <button
          type="button"
          onClick={() => { setActiveTab("access"); setSuccess(null); setError(null); }}
          className={`pb-3 text-xs uppercase font-mono tracking-wider transition-all border-b-2 cursor-pointer ${
            activeTab === "access"
              ? "border-cyan-500 text-cyan-400 font-bold"
              : "border-transparent text-slate-400 hover:text-slate-200"
          }`}
        >
          [02] Access Control & IP Registry
        </button>
      </div>

      {success && (
        <div className="p-3 bg-cyan-500/10 border border-cyan-500/30 rounded-lg text-cyan-400 text-xs font-mono text-center">
          [SYS_SUCCESS]: {success}
        </div>
      )}

      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-455 text-xs font-mono text-center">
          [SYS_DENIED]: {error}
        </div>
      )}

      {loading ? (
        <div className="flex flex-col items-center justify-center py-12 space-y-3">
          <div className="w-8 h-8 border-3 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
          <p className="font-mono text-[11px] text-slate-400">Consulting administrative records...</p>
        </div>
      ) : activeTab === "logs" ? (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* ANALYST DIRECTORY COLUMN */}
          <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4 h-fit">
            <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800 pb-2 flex items-center gap-2">
              <Users className="w-4.5 h-4.5 text-cyan-400" /> Analyst Directory
            </h3>

            <div className="space-y-3 max-h-96 overflow-y-auto">
              {users.map((u) => (
                <div key={u.id} className="p-3 bg-slate-950 border border-slate-850 rounded-xl space-y-1 font-mono text-xs text-slate-400 relative">
                  <span className="block text-slate-200 font-bold font-sans">{u.username}</span>
                  <div className="flex items-center gap-1.5 text-[10px] text-slate-500">
                    <Mail className="w-3 h-3 text-slate-500" /> <span>{u.email}</span>
                  </div>
                  <div className="flex items-center justify-between mt-2 pt-2 border-t border-slate-900 border-dashed text-[10px]">
                    <span className="text-slate-500">Clearance level:</span>
                    <strong className="text-cyan-400 uppercase">{u.role}</strong>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* AUDIT LOG TRAIL */}
          <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 border-b border-slate-800 pb-2">
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide flex items-center gap-2">
                <Terminal className="w-4.5 h-4.5 text-cyan-400" /> Cryptographic System Audit log
              </h3>

              <button
                type="button"
                onClick={handleClearLogs}
                className="inline-flex items-center gap-1.5 text-[10px] text-rose-500 border border-slate-800 hover:border-rose-500/20 hover:bg-rose-500/5 bg-slate-950 px-2.5 py-1.5 rounded-lg font-mono transition-all cursor-pointer focus:outline-none self-start sm:self-auto"
                title="Wipe Logs Records"
              >
                <Trash2 className="w-3.5 h-3.5" /> Purge Logs Trace
              </button>
            </div>

            {/* Logs Timeline lists */}
            <div className="space-y-3.5 max-h-[420px] overflow-y-auto pr-1">
              {logs.length > 0 ? (
                logs.map((log) => {
                  const dateStr = new Date(log.createdAt).toLocaleTimeString(undefined, {
                    hour: "numeric",
                    minute: "numeric",
                    second: "numeric"
                  }) + " " + new Date(log.createdAt).toLocaleDateString();

                  return (
                    <div key={log.id} className="p-3 bg-slate-950 border border-slate-850 rounded-xl space-y-1.5 font-mono text-xs">
                      <div className="flex items-center justify-between text-[10px] text-slate-550 border-b border-slate-900 pb-1.5 font-bold">
                        <span>ACTION: {log.action.toUpperCase()}</span>
                        <span>{dateStr}</span>
                      </div>
                      <p className="text-slate-300 font-sans leading-relaxed text-[11px] pt-1">{log.details}</p>
                      <div className="flex items-center justify-between text-[9px] text-slate-600 font-mono pt-1">
                        <span>Identity coordinates: <strong className="text-cyan-500 font-semibold">{log.username}</strong></span>
                        <span>Ip trace: {log.ip}</span>
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-12 text-slate-550 font-mono">
                  [SYS_WARN]: System files audit trail is completely clean. No log activity registered.
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        /* ACCESS CONTROL AND IP REGISTRY SCREEN */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          
          {/* BAN IP FORM & CURRENT LIST */}
          <div className="space-y-6">
            {/* Form */}
            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800 pb-2 flex items-center gap-2">
                <ShieldX className="w-4.5 h-4.5 text-rose-500" /> Contain IP Address
              </h3>
              
              <div className="space-y-3 text-xs">
                <div>
                  <label className="block text-slate-400 font-mono mb-1">IP TARGET COORDINATE</label>
                  <input
                    type="text"
                    value={banIpInput}
                    onChange={(e) => setBanIpInput(e.target.value)}
                    placeholder="e.g. 185.220.101.44"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-200 font-mono focus:border-rose-500 focus:outline-none transition-colors"
                  />
                </div>
                <div>
                  <label className="block text-slate-400 font-mono mb-1">REASON / CONTEXT OF BREACH</label>
                  <textarea
                    rows={2}
                    value={banReasonInput}
                    onChange={(e) => setBanReasonInput(e.target.value)}
                    placeholder="e.g. Dictionary attack on analyst gates"
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl px-3 py-2 text-slate-255 focus:border-rose-500 focus:outline-none transition-colors font-sans"
                  />
                </div>
                <button
                  type="button"
                  onClick={() => handleBanIp(banIpInput, banReasonInput)}
                  className="w-full bg-gradient-to-r from-rose-700 to-rose-600 hover:from-rose-600 hover:to-rose-500 border border-rose-500/30 text-white font-mono font-bold py-2.5 rounded-xl transition-all cursor-pointer flex items-center justify-center gap-2"
                >
                  <Ban className="w-3.5 h-3.5" /> Enforce IP Containment
                </button>
              </div>
            </div>

            {/* Banned IP Lists */}
            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800 pb-2 flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <Globe className="w-4.5 h-4.5 text-rose-500" /> Containment Registry
                </span>
                <span className="bg-rose-500/10 border border-rose-500/20 text-rose-455 px-2 py-0.5 rounded-full text-[10px] font-mono">
                  {bannedIps.length} Node{bannedIps.length === 1 ? "" : "s"}
                </span>
              </h3>

              <div className="space-y-3 max-h-72 overflow-y-auto pr-1">
                {bannedIps.length > 0 ? (
                  bannedIps.map((b) => (
                    <div key={b.ip} className="p-3 bg-slate-950/60 border border-slate-850 rounded-xl space-y-2 text-xs relative group">
                      <div className="flex items-center justify-between">
                        <span className="font-mono text-rose-400 font-bold">{b.ip}</span>
                        <button
                          type="button"
                          onClick={() => handleUnbanIp(b.ip)}
                          className="p-1 px-2 border border-slate-800 hover:border-cyan-500/30 text-slate-400 hover:text-cyan-400 rounded-lg font-mono text-[9px] hover:bg-cyan-500/5 transition-all cursor-pointer"
                          title="Whiltelist IP"
                        >
                          <Unlock className="w-3 h-3 inline mr-1" /> Unban
                        </button>
                      </div>
                      <p className="text-slate-400 text-[11px] leading-relaxed italic">
                        "{b.reason}"
                      </p>
                      <div className="text-[9px] text-slate-500 font-mono text-right">
                        Blacklisted: {new Date(b.createdAt).toLocaleDateString()}
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center py-8 text-slate-550 text-xs font-mono">
                    [REGISTRY_EMPTY]: No IP blocks are currently active on the firewalls.
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* LOGIN TELEMETRY HISTORICAL FEED */}
          <div className="lg:col-span-2 bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
            <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800 pb-2 flex items-center gap-2">
              <Clock className="w-4.5 h-4.5 text-cyan-400" /> SOC Login Threat Intelligence Feed
            </h3>

            <div className="space-y-3 max-h-[500px] overflow-y-auto pr-1">
              {loginAttempts.length > 0 ? (
                loginAttempts.map((attempt) => {
                  const dateStr = new Date(attempt.createdAt).toLocaleTimeString(undefined, {
                    hour: "numeric",
                    minute: "numeric",
                    second: "numeric"
                  }) + " " + new Date(attempt.createdAt).toLocaleDateString();

                  const isBanned = bannedIps.some((b) => b.ip === attempt.ip);

                  return (
                    <div key={attempt.id} className="p-3.5 bg-slate-950 border border-slate-850 rounded-xl space-y-3 font-mono text-xs hover:border-slate-800 transition-colors">
                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2 text-[10px] text-slate-500">
                        <div className="flex items-center gap-2">
                          <span className="font-bold text-slate-400">TARGET ACCOUNT:</span>
                          <span className="bg-slate-900 border border-slate-800 text-slate-300 px-2 py-0.5 rounded font-bold font-sans">
                            {attempt.username}
                          </span>
                        </div>
                        <span className="text-[10px] text-slate-500 font-semibold">{dateStr}</span>
                      </div>

                      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3 pt-1">
                        <div className="flex items-center gap-4">
                          <div>
                            <span className="text-slate-500 text-[10px] block font-semibold">CLIENT IP ADDR</span>
                            <span className="text-slate-300 text-xs font-bold leading-relaxed">{attempt.ip}</span>
                          </div>
                          <div>
                            <span className="text-slate-500 text-[10px] block font-semibold">SESSION RESULTS</span>
                            <span className={`px-2 py-0.5 rounded border text-[9px] font-bold block w-fit ${
                              attempt.status === "SUCCESS"
                                ? "border-emerald-500/20 bg-emerald-500/10 text-emerald-400"
                                : attempt.status === "FAILED"
                                ? "border-rose-500/20 bg-rose-500/10 text-rose-450"
                                : "border-amber-500/20 bg-amber-500/10 text-amber-400"
                            }`}>
                              ● {attempt.status}
                            </span>
                          </div>
                        </div>

                        {!isBanned ? (
                          <button
                            type="button"
                            onClick={() => {
                              setBanIpInput(attempt.ip);
                              setBanReasonInput(`Blacklisted following log-in attempt on account "${attempt.username}"`);
                              setError(null);
                            }}
                            className="bg-rose-500/10 hover:bg-rose-500/20 hover:text-rose-400 border border-slate-850 hover:border-rose-500/30 text-slate-400 px-2.5 py-1.5 rounded-lg text-[10px] transition-all cursor-pointer flex items-center gap-1 font-mono focus:outline-none"
                          >
                            <Ban className="w-3 h-3 text-rose-500" /> Ban IP Client
                          </button>
                        ) : (
                          <div className="flex items-center gap-1.5 text-rose-500/80 bg-rose-500/5 px-2 py-1 border border-rose-500/10 rounded-lg text-[10px] font-mono">
                            <AlertOctagon className="w-3.5 h-3.5" /> BANNED NODE
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })
              ) : (
                <div className="text-center py-12 text-slate-550 font-mono">
                  [SYS_WARN]: Access telemetry database holds no records.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
