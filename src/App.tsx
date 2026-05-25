/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from "react";
import { Shield, Mail, Terminal, Lock, Cpu, Globe, CheckCircle, LogOut, LogIn, Users, BarChart2, PieChart, Database, Activity, FileText } from "lucide-react";

// Components
import { LandingPage } from "./components/LandingPage.js";
import { Auth } from "./components/Auth.js";
import { Dashboard } from "./components/Dashboard.js";
import { Analyzer } from "./components/Analyzer.js";
import { MLWorkbench } from "./components/MLWorkbench.js";
import { AdminPanel } from "./components/AdminPanel.js";

// Types
import { UserRole, ScanRecord, DashboardStats } from "./types.js";

type Tab = "home" | "login" | "dashboard" | "analyzer" | "ml" | "admin";

export default function App() {
  const [activeTab, setActiveTab] = useState<Tab>("home");
  const [token, setToken] = useState<string | null>(localStorage.getItem("soc_analyst_token"));
  const [currentUser, setCurrentUser] = useState<{ username: string; email: string; role: UserRole } | null>(null);
  
  // Dashboard Metrics
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(false);

  // Selected threat record for Analyzer
  const [selectedRecord, setSelectedRecord] = useState<ScanRecord | null>(null);

  // Auto-restore login on startup
  useEffect(() => {
    if (token) {
      try {
        const decoded = JSON.parse(atob(token.split(".")[1]));
        const isExpired = decoded.exp * 1000 < Date.now();
        if (isExpired) {
          handleLogout();
        } else {
          setCurrentUser({
            username: decoded.username,
            email: decoded.email || `${decoded.username}@agency.com`,
            role: decoded.role as UserRole
          });
          // Restore to dashboard
          setActiveTab("dashboard");
        }
      } catch (err) {
        console.error("Failed to restore session states:", err);
        handleLogout();
      }
    }
  }, [token]);

  // Load stats when user acts or registers
  useEffect(() => {
    if (currentUser && token) {
      fetchDashboardStats();
    }
  }, [currentUser, token]);

  const fetchDashboardStats = async () => {
    setStatsLoading(true);
    try {
      const response = await fetch("/api/dashboard-stats", {
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      const data = await response.json();
      if (response.ok) {
        setStats(data);
      } else {
        console.error("Failed to load pipeline stats:", data.error);
      }
    } catch (err) {
      console.error("Network transaction error fetching stats:", err);
    } finally {
      setStatsLoading(false);
    }
  };

  const handleAuthSuccess = (newToken: string, user: { username: string; email: string; role: UserRole }) => {
    localStorage.setItem("soc_analyst_token", newToken);
    setToken(newToken);
    setCurrentUser(user);
    setActiveTab("dashboard");
  };

  const handleLogout = () => {
    localStorage.removeItem("soc_analyst_token");
    setToken(null);
    setCurrentUser(null);
    setActiveTab("home");
    setSelectedRecord(null);
  };

  // Callback to execute new threats uploads
  const handleAnalyzeThreat = async (payload: {
    subject: string;
    sender: string;
    body: string;
    headers?: string;
    attachments?: { name: string; size: number; base64: string }[];
  }): Promise<ScanRecord> => {
    if (!token) throw new Error("Private investigation privileges expired. login again.");

    const response = await fetch("/api/upload-email", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Threat pipeline compilation failed.");
    }

    // Refresh database statistics
    fetchDashboardStats();
    setSelectedRecord(data);
    return data;
  };

  // Administrative removal helper
  const handleDeleteRecord = async (id: string) => {
    if (!token) return;
    if (!window.confirm("CONFIRMATION REQUIRED: Are you sure you want to permanently delete this threat incident scan record from security databases?")) {
      return;
    }

    try {
      const response = await fetch(`/api/admin/investigations/${id}`, {
        method: "DELETE",
        headers: {
          "Authorization": `Bearer ${token}`
        }
      });
      if (response.ok) {
        fetchDashboardStats();
      } else {
        const err = await response.json();
        alert(err.error || "Action rejected.");
      }
    } catch (err) {
      console.error("Administrative transaction failed:", err);
    }
  };

  const handleViewRecordFromTable = (record: ScanRecord) => {
    setSelectedRecord(record);
    setActiveTab("analyzer");
  };

  return (
    <div className="min-h-screen bg-[#05070a] text-slate-200 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-300 font-sans">
      
      {/* PROFESSIONAL NAV BAR */}
      <nav className="sticky top-0 bg-[#0b111a] border-b border-cyan-900/30 shadow-lg z-50 px-4 sm:px-6">
        <div className="max-w-7xl mx-auto flex items-center justify-between h-16">
          
          {/* LOGO GRID */}
          <button
            onClick={() => {
              setActiveTab("home");
              setSelectedRecord(null);
            }}
            className="flex items-center gap-3 font-sans focus:outline-none cursor-pointer text-left"
          >
            <div className="w-8 h-8 bg-cyan-500 flex items-center justify-center rounded-md border border-cyan-300 shadow-[0_0_10px_rgba(6,182,212,0.5)]">
              <svg className="w-5 h-5 text-black" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"></path>
              </svg>
            </div>
            <h1 className="text-base font-bold tracking-tight text-white uppercase font-sans">
              PhishGuard <span className="text-cyan-400">AI</span>
            </h1>
          </button>

          {/* ACTIVE MODEL INDICATOR */}
          <div className="hidden lg:flex items-center space-x-2 text-xs font-mono ml-4">
            <span className="w-2 h-2 rounded-full bg-emerald-500 shadow-[0_0_8px_#10b981]"></span>
            <span className="text-slate-400 font-bold uppercase tracking-wider">MODEL STATUS: ACTIVE</span>
          </div>

          {/* CENTRE TABS BAR */}
          <nav className="hidden md:flex items-center gap-2 text-xs font-mono ml-auto mr-4">
            <button
              onClick={() => {
                setActiveTab("home");
                setSelectedRecord(null);
              }}
              className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                activeTab === "home" 
                  ? "bg-[#0f172a] text-cyan-400 border-slate-800 shadow-inner" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              Overview
            </button>

            {currentUser && (
              <>
                <button
                  onClick={() => {
                    setActiveTab("dashboard");
                    setSelectedRecord(null);
                  }}
                  className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                    activeTab === "dashboard" 
                      ? "bg-[#0f172a] text-cyan-400 border-slate-800 shadow-inner" 
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  SOC Dashboard
                </button>

                <button
                  onClick={() => setActiveTab("analyzer")}
                  className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                    activeTab === "analyzer" 
                      ? "bg-[#0f172a] text-cyan-400 border-slate-800 shadow-inner" 
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  Ingest Scan Desk
                </button>

                <button
                  onClick={() => {
                    setActiveTab("ml");
                    setSelectedRecord(null);
                  }}
                  className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                    activeTab === "ml" 
                      ? "bg-[#0f172a] text-cyan-400 border-slate-800 shadow-inner" 
                      : "border-transparent text-slate-400 hover:text-slate-200"
                  }`}
                >
                  ML Lab
                </button>

                {currentUser.role === UserRole.ADMIN && (
                  <button
                    onClick={() => {
                      setActiveTab("admin");
                      setSelectedRecord(null);
                    }}
                    className={`px-3 py-1.5 rounded-lg border transition-all cursor-pointer ${
                      activeTab === "admin" 
                        ? "bg-[#0f172a] text-cyan-400 border-slate-800 shadow-inner" 
                        : "border-transparent text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    Control Room
                  </button>
                )}
              </>
            )}
          </nav>

          {/* USER SESSION ACTIONS */}
          <div className="flex items-center gap-3">
            {currentUser ? (
              <div className="flex items-center gap-3.5 border-l border-slate-800 pl-4">
                <div className="hidden sm:block text-right text-[10px] leading-tight font-mono">
                  <p className="text-slate-300 font-bold uppercase">{currentUser.username}</p>
                  <p className="text-cyan-500 font-semibold">{currentUser.role === UserRole.ADMIN ? "Senior Admin" : "Security Analyst"}</p>
                </div>
                
                <div className="w-8.5 h-8.5 rounded-full bg-slate-800 border border-slate-700 flex items-center justify-center font-bold text-[11px] text-cyan-400 font-mono shadow-inner shrink-0">
                  {currentUser.username.substring(0, 2).toUpperCase()}
                </div>
                
                <button
                  onClick={handleLogout}
                  className="flex items-center gap-1 bg-rose-950/20 hover:bg-rose-950/40 border border-rose-900/30 text-rose-400 text-xs font-mono py-1.5 px-3 rounded-lg cursor-pointer transition-all focus:outline-none"
                  title="Sign out Analyst session"
                >
                  <LogOut className="w-3.5 h-3.5 shrink-0" /> Sign Out
                </button>
              </div>
            ) : (
              activeTab !== "login" && (
                <button
                  onClick={() => setActiveTab("login")}
                  className="flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-500 text-black font-semibold text-xs py-2 px-4 rounded-lg cursor-pointer shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all focus:outline-none border border-cyan-400/40 font-mono"
                >
                  <LogIn className="w-4 h-4" /> Partner Access
                </button>
              )
            )}
          </div>
        </div>
      </nav>

      {/* MOBILE WARNING HELPER */}
      <div className="md:hidden bg-cyan-500/10 border-b border-cyan-500/20 text-[10px] text-cyan-400 p-2 text-center font-mono">
        💻 Pro SOC tip: This terminal operates optimally on wider desktop screens.
      </div>

      {/* MAIN CONTAINER PLATFORM */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 lg:p-8">
        
        {/* TAB FLOW SWITCHES */}
        {activeTab === "home" && (
          <LandingPage
            onStartAnalysis={() => {
              if (currentUser) {
                setActiveTab("analyzer");
              } else {
                setActiveTab("login");
              }
            }}
            onLoginClick={() => setActiveTab("login")}
            isAuthenticated={!!currentUser}
          />
        )}

        {activeTab === "login" && (
          <Auth onAuthSuccess={handleAuthSuccess} />
        )}

        {currentUser && token && (
          <>
            {activeTab === "dashboard" && stats && (
              <Dashboard
                stats={stats}
                loading={statsLoading}
                onViewRecord={handleViewRecordFromTable}
                onDeleteRecord={handleDeleteRecord}
                currentUserRole={currentUser.role}
              />
            )}

            {activeTab === "analyzer" && (
              <Analyzer
                onAnalyze={handleAnalyzeThreat}
                selectedRecord={selectedRecord}
                onClearSelection={() => setSelectedRecord(null)}
                pastRecords={stats?.recentInvestigations || []}
              />
            )}

            {activeTab === "ml" && (
              <MLWorkbench currentUserRole={currentUser.role} token={token} />
            )}

            {activeTab === "admin" && (
              <AdminPanel currentUserRole={currentUser.role} token={token} />
            )}
          </>
        )}
      </main>

      {/* THEME ALIGNED SOC FOOTER */}
      <footer className="px-6 py-4 bg-[#05070a] border-t border-slate-800 flex flex-col md:flex-row justify-between items-center text-[10px] gap-2 shrink-0">
        <div className="flex space-x-6 text-slate-500 font-mono">
          <span>SYSTEM VERSION: 2.4.0-STABLE</span>
          <span>PIPELINE: VECTORS & COGNITIVE MODEL</span>
          <span>DB: CACHE STORAGE_01</span>
        </div>
        <div className="text-cyan-500/50 uppercase tracking-widest font-mono text-[9px]">
          &copy; 2026 SOC-INTELLIGENCE | CLOUD-READY PHISHING PROTECTION
        </div>
      </footer>
    </div>
  );
}
