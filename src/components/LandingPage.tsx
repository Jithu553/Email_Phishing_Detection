/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from "react";
import { Shield, Mail, Terminal, Lock, Cpu, Globe, CheckCircle, Smartphone, ArrowRight, Zap, Database, FileText } from "lucide-react";

interface LandingProps {
  onStartAnalysis: () => void;
  onLoginClick: () => void;
  isAuthenticated: boolean;
}

export function LandingPage({ onStartAnalysis, onLoginClick, isAuthenticated }: LandingProps) {
  return (
    <div className="space-y-24 pb-16">
      {/* 1. HERO SECTION */}
      <section className="relative py-20 overflow-hidden text-center max-w-4xl mx-auto px-4 font-sans">
        {/* Futuristic Grid Canvas */}
        <div className="absolute inset-0 bg-[#05070a] bg-[radial-gradient(ellipse_at_top,_var(--tw-gradient-stops))] from-cyan-950/20 via-[#05070a] to-[#05070a] opacity-40 -z-10"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-cyan-500/10 blur-[100px] rounded-full -z-10"></div>

        <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-500/10 border border-cyan-500/30 rounded-full text-cyan-400 text-xs font-mono mb-8 uppercase tracking-wider animate-pulse">
          <Zap className="w-3.5 h-3.5" /> Intelligent Threat Recon & Forensic Suite
        </div>

        <h1 className="text-4xl sm:text-6xl font-black tracking-tight text-white mb-6 leading-tight font-sans">
          AI-Driven Phishing Detection <br />
          <span className="bg-gradient-to-r from-cyan-400 via-sky-300 to-blue-500 text-transparent bg-clip-text">
            & Forensic Investigations
          </span>
        </h1>

        <p className="text-base text-slate-300 max-w-2xl mx-auto mb-10 leading-relaxed font-sans">
          Inbound threat intelligence and automated mail audit terminal. Combine machine learning TF-IDF classifiers with deep Gemini AI forensics, header hops analysis, URL inspection, and cryptographical attachment sandbox audits.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
          <button
            onClick={onStartAnalysis}
            className="w-full sm:w-auto flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 border border-cyan-400/30 text-white font-bold py-3.5 px-8 rounded-xl shadow-[0_0_15px_rgba(6,182,212,0.3)] hover:shadow-[0_0_25px_rgba(6,182,212,0.6)] cursor-pointer transition-all font-sans text-sm"
          >
            Launch Investigation Desk <ArrowRight className="w-5 h-5" />
          </button>
          
          {!isAuthenticated && (
            <button
              onClick={onLoginClick}
              className="w-full sm:w-auto bg-slate-900/80 hover:bg-slate-800 text-slate-200 border border-slate-705 font-bold py-3.5 px-8 rounded-xl cursor-pointer transition-all font-sans text-sm"
            >
              Partner Authorized Login
            </button>
          )}

          <a
            href="#features-target"
            className="w-full sm:w-auto text-slate-400 hover:text-slate-200 text-sm font-mono transition-all underline decoration-cyan-500/40 underline-offset-4"
          >
            Read Technical Docs
          </a>
        </div>
      </section>

      {/* 2. REAL-TIME THREAT CORE TICKER STATS */}
      <section className="max-w-6xl mx-auto px-4 font-sans">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6 bg-[#0b111a] border border-slate-800/85 p-8 rounded-2xl relative shadow-2xl">
          <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 blur-[50px] rounded-full pointer-events-none"></div>
          
          <div className="text-center md:border-r border-slate-800/60 p-2">
            <p className="text-4xl font-extrabold text-white tracking-tight font-mono">14,282</p>
            <p className="text-xs font-mono uppercase text-slate-500 mt-2 font-bold tracking-wider">Mails Analyzed</p>
          </div>
          <div className="text-center md:border-r border-slate-800/60 p-2">
            <p className="text-4xl font-extrabold text-rose-500 tracking-tight font-mono">2,419</p>
            <p className="text-xs font-mono uppercase text-slate-500 mt-2 font-bold tracking-wider">Threats Neutralized</p>
          </div>
          <div className="text-center md:border-r border-slate-800/60 p-2">
            <p className="text-4xl font-extrabold text-cyan-400 tracking-tight font-mono">42ms</p>
            <p className="text-xs font-mono uppercase text-slate-500 mt-2 font-bold tracking-wider">Avg Prediction Time</p>
          </div>
          <div className="text-center p-2">
            <p className="text-4xl font-extrabold text-amber-500 tracking-tight font-mono">12</p>
            <p className="text-xs font-mono uppercase text-slate-500 mt-2 font-bold tracking-wider">Active Investigations</p>
          </div>
        </div>
      </section>

      {/* 3. HARDWARE FEATURES BENTO GRID */}
      <section id="features-target" className="max-w-6xl mx-auto px-4 space-y-12">
        <div className="text-center max-w-xl mx-auto">
          <h2 className="text-3xl font-black text-white tracking-tight">System Core Architecture</h2>
          <p className="text-sm text-slate-400 mt-2">
            A cohesive full-spectrum investigation framework engineered to analyze threats from multiple distinct cyber indicators.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1: NLP Machine Learning */}
          <div className="bg-[#0b111a] border border-slate-800/80 hover:border-cyan-500/30 p-6 rounded-2xl transition-all relative group overflow-hidden shadow-inner">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 blur-[20px] rounded-full group-hover:bg-cyan-500/10"></div>
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl inline-block mb-4 border border-cyan-500/20">
              <Cpu className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">TF-IDF Classifier Engine</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Supervised machine learning pipeline evaluating email text structure. Calculates feature coordinates and generates instant prediction classifications and percentage thresholds.
            </p>
          </div>

          {/* Card 2: Header Analyzer */}
          <div className="bg-[#0b111a] border border-slate-800/80 hover:border-cyan-500/35 p-6 rounded-2xl transition-all relative group overflow-hidden shadow-inner">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 blur-[20px] rounded-full group-hover:bg-cyan-500/10"></div>
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl inline-block mb-4 border border-cyan-500/20">
              <Terminal className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">RFC Header Analyzer</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Dissects transit routes, extracting sender IP coordinates, verifying SPF authorized ranges, checking DKIM token alignments, and auditing DMARC enforcement breaches.
            </p>
          </div>

          {/* Card 3: URL Deep Scan */}
          <div className="bg-[#0b111a] border border-slate-800/80 hover:border-cyan-500/30 p-6 rounded-2xl transition-all relative group overflow-hidden shadow-inner">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 blur-[20px] rounded-full group-hover:bg-cyan-500/10"></div>
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl inline-block mb-4 border border-cyan-500/20">
              <Globe className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Hyperlink Safety Audits</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Slices inbound page links. Audits SSL HTTPS requirements, tracks shortened redirect triggers, scans domain age thresholds, and triggers risk coefficients on lexical keywords.
            </p>
          </div>

          {/* Card 4: Attachment Sanitizer */}
          <div className="bg-[#0b111a] border border-slate-800/80 hover:border-cyan-500/30 p-6 rounded-2xl transition-all relative group overflow-hidden shadow-inner">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 blur-[20px] rounded-full group-hover:bg-cyan-500/10"></div>
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl inline-block mb-4 border border-cyan-500/20">
              <Lock className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Attachment Sandbox Analysis</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Reviews file metadata, generates high-quality SHA-256 evidence logs MD5 hashes, identifies hidden dangerous executable strings, and validates potential macro vectors.
            </p>
          </div>

          {/* Card 5: Intelligent LLM Forensic review */}
          <div className="bg-[#0b111a] border border-slate-800/80 hover:border-cyan-500/30 p-6 rounded-2xl transition-all relative group overflow-hidden shadow-inner">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 blur-[20px] rounded-full group-hover:bg-cyan-500/10"></div>
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl inline-block mb-4 border border-cyan-500/20">
              <Shield className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Gemini AI Threat Forensics</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Utilizes the Gemini 3.5-flash expert LLM on the server to reconstruct active threat profiles, social-gullibility strategy maps, and structured step-by-step mitigation chronologies.
            </p>
          </div>

          {/* Card 6: Downloadable Forensic Reports */}
          <div className="bg-[#0b111a] border border-slate-800/80 hover:border-cyan-500/30 p-6 rounded-2xl transition-all relative group overflow-hidden shadow-inner">
            <div className="absolute top-0 right-0 w-24 h-24 bg-cyan-500/5 blur-[20px] rounded-full group-hover:bg-cyan-500/10"></div>
            <div className="p-3 bg-cyan-500/10 text-cyan-400 rounded-xl inline-block mb-4 border border-cyan-500/20">
              <FileText className="w-6 h-6" />
            </div>
            <h3 className="text-base font-bold text-white mb-2">Incident Forensic Reports</h3>
            <p className="text-xs text-slate-400 leading-relaxed">
              Outputs full clean forensic dossiers detailing header anomalies, malicious URLs list, threat scores, file hashes evidence, incident timeline details, and ready printable logs.
            </p>
          </div>
        </div>
      </section>

      {/* 4. VISUAL WORKFLOW DIAGRAM */}
      <section className="bg-[#0b111a]/50 border-t border-b border-cyan-950/20 py-16 px-4">
        <div className="max-w-6xl mx-auto font-sans">
          <div className="text-center max-w-xl mx-auto mb-12">
            <h2 className="text-3xl font-black text-white tracking-tight">Threat Ingress Analysis Pipeline</h2>
            <p className="text-sm text-slate-400 mt-2">
              Visualizing the cryptographic progression from raw email intake to final executive security scoring layout.
            </p>
          </div>

          <div className="flex flex-col lg:flex-row items-center justify-center gap-6 lg:gap-3 text-center">
            {/* Step 1 */}
            <div className="flex-1 bg-[#0b111a] border border-slate-800 p-6 rounded-xl relative w-full max-w-xs shadow-inner">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 px-3 py-1 bg-slate-950 border border-slate-800 text-[10px] font-mono rounded-full text-slate-400">STAGE 01</div>
              <Mail className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
              <h4 className="text-xs font-bold text-white font-mono uppercase mb-1">Electronic Intake</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">System parses text body, separates header records and gathers attachments binary.</p>
            </div>

            {/* Line arrow */}
            <div className="h-6 w-0.5 lg:h-0.5 lg:w-8 bg-slate-800"></div>

            {/* Step 2 */}
            <div className="flex-1 bg-[#0b111a] border border-slate-800 p-6 rounded-xl relative w-full max-w-xs shadow-inner">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 px-3 py-1 bg-slate-950 border border-slate-800 text-[10px] font-mono rounded-full text-slate-400">STAGE 02</div>
              <Cpu className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
              <h4 className="text-xs font-bold text-white font-mono uppercase mb-1">ML classification</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">TF-IDF text vector analyzer tokenizes words and applies logistic regressions feature scoring.</p>
            </div>

            {/* Line arrow */}
            <div className="h-6 w-0.5 lg:h-0.5 lg:w-8 bg-slate-800"></div>

            {/* Step 3 */}
            <div className="flex-1 bg-[#0b111a] border border-slate-800 p-6 rounded-xl relative w-full max-w-xs shadow-inner">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 px-3 py-1 bg-slate-950 border border-slate-800 text-[10px] font-mono rounded-full text-slate-400">STAGE 03</div>
              <Database className="w-8 h-8 text-cyan-400 mx-auto mb-3" />
              <h4 className="text-xs font-bold text-white font-mono uppercase mb-1">Multi-Vector Sandbox</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">Headers are audited, attachments hashed, and suspicious links checked against global blacklists.</p>
            </div>

            {/* Line arrow */}
            <div className="h-6 w-0.5 lg:h-0.5 lg:w-8 bg-slate-800"></div>

            {/* Step 4 */}
            <div className="flex-1 bg-[#0b111a] border border-cyan-500/20 p-6 rounded-xl relative w-full max-w-xs shadow-[0_0_15px_rgba(6,182,212,0.06)]">
              <div className="absolute -top-3 left-1/2 transform -translate-x-1/2 px-3 py-1 bg-slate-950 border border-cyan-500/25 text-[10px] font-mono rounded-full text-cyan-400">STAGE 04</div>
              <Shield className="w-8 h-8 text-cyan-400 mx-auto mb-3 animate-pulse" />
              <h4 className="text-xs font-bold text-white font-mono uppercase mb-1">SOC Forensic report</h4>
              <p className="text-[11px] text-slate-400 leading-relaxed">Dynamic threat score calculated and combined with Gemini AI deep analytics payload.</p>
            </div>
          </div>
        </div>
      </section>

      {/* 5. INTUITIVE ABOUT SECTION */}
      <section className="max-w-6xl mx-auto px-4 grid grid-cols-1 md:grid-cols-2 gap-12 items-center font-sans">
        <div className="space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 bg-cyan-500/10 border border-cyan-500/30 rounded-full text-cyan-400 text-xs font-mono">
            RESEARCH & DEVELOPMENT ACADEMIC ALIGNMENT
          </div>
          <h2 className="text-3xl font-black text-white tracking-tight leading-tight">
            Designed for Modern Cyber Security Demonstrations
          </h2>
          <p className="text-slate-350 leading-relaxed text-sm">
            This platform acts as an ideal final-year academic demonstration or professional SOC analyst portfolio project. It addresses the real-world operational challenges of email-based social engineering compromises by combining structured mathematical classifiers with semantic Large Language Model (LLM) reasoning.
          </p>
          
          <ul className="space-y-3 font-mono text-xs text-slate-400">
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" /> Complete multi-role Partner and Administrator authentication.
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" /> Operational Machine Learning workbench to retrain classifiers.
            </li>
            <li className="flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-cyan-400 shrink-0" /> Cryptographically trace file attachment signatures.
            </li>
          </ul>
        </div>

        <div className="bg-[#0b111a] border border-slate-850 p-8 rounded-2xl relative font-mono text-xs text-slate-300 shadow-2xl">
          <div className="absolute top-2 left-4 flex gap-1.5 pointer-events-none">
            <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-amber-500"></span>
            <span className="w-2.5 h-2.5 rounded-full bg-cyan-500 shadow-[0_0_6px_#06b6d4]"></span>
          </div>
          <div className="mt-4 space-y-2 border-t border-slate-800 pt-4 text-cyan-400/90 leading-relaxed">
            <p># ./phishguard-terminal --audit-system</p>
            <p className="text-slate-500">[SYSTEM]: Initializing TF-IDF neural vector nodes...</p>
            <p className="text-slate-300">[MODEL]: Loaded dictionary (Size: 2,422, Weights: Logarithmic)</p>
            <p className="text-slate-500">[SYSTEM]: Checking Gemini 3.5-flash pipeline connectivity...</p>
            <p className="text-cyan-400">[ONLINE]: Secure API key authenticated successfully via secrets engine.</p>
            <p className="text-slate-300"># Ready for electronic mail ingest audits. Listening on port :3000...</p>
          </div>
        </div>
      </section>
    </div>
  );
}
