/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { Shield, LogIn, UserPlus, Lock, Mail, User } from "lucide-react";
import { UserRole } from "../types.js";

interface AuthProps {
  onAuthSuccess: (token: string, user: { username: string; email: string; role: UserRole }) => void;
}

export function Auth({ onAuthSuccess }: AuthProps) {
  const [isLogin, setIsLogin] = useState(true);
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<UserRole>(UserRole.ANALYST);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);

    const payload = isLogin 
      ? { username, password }
      : { username, email, password, role };

    const endpoint = isLogin ? "/api/login" : "/api/register";

    try {
      const response = await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
      });
      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error || "Authentication procedure failure.");
      }

      onAuthSuccess(data.token, data.user);
    } catch (err: any) {
      setError(err.message || "A network transaction failure occurred.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8 font-sans">
      <div className="max-w-md w-full space-y-8 bg-[#0b111a] border border-cyan-900/30 p-8 rounded-2xl shadow-[0_0_50px_rgba(6,182,212,0.1)] relative overflow-hidden backdrop-blur-xl">
        {/* Glow Element */}
        <div className="absolute top-0 left-1/4 w-1/2 h-1 bg-gradient-to-r from-cyan-500 via-sky-400 to-blue-500 rounded-full opacity-50"></div>

        <div className="text-center">
          <div className="inline-flex items-center justify-center p-3 rounded-full bg-cyan-500/10 text-cyan-400 mb-4 border border-cyan-500/20 shadow-[0_0_20px_rgba(6,182,212,0.2)]">
            <Shield className="w-10 h-10 animate-pulse" />
          </div>
          <h2 className="text-3xl font-black text-slate-100 tracking-tight font-sans">
            {isLogin ? "Analyst Terminal Access" : "Provision Partner Identity"}
          </h2>
          <p className="mt-2 text-xs text-slate-400 font-sans">
            {isLogin 
              ? "Access the digital forensics and machine learning workbench" 
              : "Register a secure cryptographic identity in the system database"}
          </p>
        </div>

        {error && (
          <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-400 text-xs font-mono text-center">
            [SYS_AUTH_FAILED]: {error}
          </div>
        )}

        <form className="mt-8 space-y-6" onSubmit={handleSubmit}>
          <div className="space-y-4">
            <div>
              <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1 font-bold tracking-wider">Terminal ID (Username)</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                  <User className="w-5 h-5 text-slate-400" />
                </span>
                <input
                  type="text"
                  required
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 bg-[#05070a] border border-slate-800 rounded-xl text-slate-100 font-sans focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-medium placeholder-slate-600 transition-all text-sm"
                  placeholder="analyst1 or admin"
                />
              </div>
            </div>

            {!isLogin && (
              <>
                <div>
                  <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1 font-bold tracking-wider">Security Email</label>
                  <div className="relative">
                    <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                      <Mail className="w-5 h-5 text-slate-400" />
                    </span>
                    <input
                      type="email"
                      required
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="w-full pl-10 pr-4 py-3 bg-[#05070a] border border-slate-800 rounded-xl text-slate-100 font-sans focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-medium placeholder-slate-600 transition-all text-sm"
                      placeholder="analyst@agency.com"
                    />
                  </div>
                </div>

                <div>
                  <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1 font-bold tracking-wider">Assigned Security Role</label>
                  <div className="grid grid-cols-2 gap-4">
                    <button
                      type="button"
                      onClick={() => setRole(UserRole.ANALYST)}
                      className={`py-2.5 px-4 rounded-xl border text-xs font-sans font-medium transition-all cursor-pointer ${
                        role === UserRole.ANALYST 
                          ? "bg-cyan-500/15 border-cyan-500 text-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.1)]" 
                          : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Security Analyst
                    </button>
                    <button
                      type="button"
                      onClick={() => setRole(UserRole.ADMIN)}
                      className={`py-2.5 px-4 rounded-xl border text-xs font-sans font-medium transition-all cursor-pointer ${
                        role === UserRole.ADMIN 
                          ? "bg-cyan-500/15 border-cyan-500 text-cyan-400 shadow-[0_0_10px_rgba(6,182,212,0.1)]" 
                          : "bg-slate-900 border-slate-800 text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      Admin
                    </button>
                  </div>
                </div>
              </>
            )}

            <div>
              <label className="block text-[10px] font-mono uppercase text-slate-400 mb-1 font-bold tracking-wider">Passphrase</label>
              <div className="relative">
                <span className="absolute inset-y-0 left-0 flex items-center pl-3 text-slate-500">
                  <Lock className="w-5 h-5 text-slate-400" />
                </span>
                <input
                  type="password"
                  required
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 bg-[#05070a] border border-slate-800 rounded-xl text-slate-100 font-sans focus:outline-none focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 font-medium placeholder-slate-600 transition-all text-sm"
                  placeholder="••••••••••••"
                />
              </div>
            </div>
          </div>

          <div className="flex items-center justify-between text-[10px] font-mono leading-tight">
            <span className="text-slate-500">
              Demo bypass: Use <strong className="text-cyan-400 font-bold">admin</strong> / <strong className="text-cyan-400 font-bold">admin123</strong>
            </span>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 py-3 px-4 rounded-xl border font-sans font-bold text-xs transition-all focus:outline-none cursor-pointer bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 border-cyan-400/30 text-white shadow-[0_4px_20px_rgba(6,182,212,0.25)] hover:shadow-[0_4px_25px_rgba(6,182,212,0.45)] disabled:opacity-50"
            >
              {loading ? (
                <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
              ) : isLogin ? (
                <>
                  <LogIn className="w-5 h-5" /> Authenticate Terminal
                </>
              ) : (
                <>
                  <UserPlus className="w-5 h-5" /> Provision Identity
                </>
              )}
            </button>
          </div>

          <div className="text-center pt-2">
            <button
              type="button"
              onClick={() => {
                setIsLogin(!isLogin);
                setError(null);
              }}
              className="text-xs font-sans font-bold text-cyan-400 hover:text-cyan-300 transition-all focus:outline-none cursor-pointer"
            >
              {isLogin 
                ? "Initiate New Analyst Profiling ➔" 
                : "Proceed to Terminal Authentication ➔"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
