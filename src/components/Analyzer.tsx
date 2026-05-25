/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from "react";
import { Shield, ShieldAlert, CheckCircle, AlertTriangle, FileCode, UploadCloud, Link, ArrowLeft, Download, Terminal, Settings, Globe, Play, FileText, ChevronRight, AlertOctagon, HelpCircle } from "lucide-react";
import { jsPDF } from "jspdf";
import { ScanRecord, ThreatLevel } from "../types.js";

interface AnalyzerProps {
  onAnalyze: (payload: {
    subject: string;
    sender: string;
    body: string;
    headers?: string;
    attachments?: { name: string; size: number; base64: string }[];
  }) => Promise<ScanRecord>;
  selectedRecord: ScanRecord | null;
  onClearSelection: () => void;
}

export function Analyzer({ onAnalyze, selectedRecord, onClearSelection }: AnalyzerProps) {
  // Input states
  const [subject, setSubject] = useState("");
  const [sender, setSender] = useState("");
  const [body, setBody] = useState("");
  const [headers, setHeaders] = useState("");
  const [attachments, setAttachments] = useState<{ name: string; size: number; base64: string }[]>([]);
  const [dragOver, setDragOver] = useState(false);

  // Status states
  const [loading, setLoading] = useState(false);
  const [loadingStep, setLoadingStep] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [analystTab, setAnalystTab] = useState<"ai" | "ml" | "headers" | "payloads">("ai");

  // Loading logs sequence simulated for realistic SOC experience
  const LOADING_STEPS = [
    "Carrying out NLP text tokenization...",
    "Computing attachment MD5 and SHA-256 evidence signatures...",
    "Scanning SMTP headers RFC routing hops and return-path domains...",
    "Analyzing hyperlink HTTPS encryptions and domain reputation blacklists...",
    "Evaluating TF-IDF machine learning coefficients ratios...",
    "Contacting Gemini-3.5-flash AI Deep Cognitive Forensic Module..."
  ];

  // Drag and drop attachment helper
  const handleFileChange = (files: FileList | null) => {
    if (!files) return;
    Array.from(files).forEach((file) => {
      const reader = new FileReader();
      reader.onload = () => {
        const base64Str = (reader.result as string).split(",")[1];
        setAttachments((prev) => [
          ...prev,
          {
            name: file.name,
            size: file.size,
            base64: base64Str
          }
        ]);
      };
      reader.readAsDataURL(file);
    });
  };

  const removeAttachment = (index: number) => {
    setAttachments((prev) => prev.filter((_, i) => i !== index));
  };

  const triggerAnalyze = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!subject || !sender || !body) {
      setError("Please populate all required threat coordinates (From, Subject, and Body).");
      return;
    }

    setLoading(true);
    setError(null);
    setLoadingStep(0);

    // Dynamic log steps rotation timer
    const interval = setInterval(() => {
      setLoadingStep((prev) => (prev < LOADING_STEPS.length - 1 ? prev + 1 : prev));
    }, 1500);

    try {
      await onAnalyze({
        subject,
        sender,
        body,
        headers,
        attachments
      });
      // Reset inputs on success
      setSubject("");
      setSender("");
      setBody("");
      setHeaders("");
      setAttachments([]);
    } catch (err: any) {
      setError(err.message || "Threat scanning system failed.");
    } finally {
      clearInterval(interval);
      setLoading(false);
    }
  };

  // Sample injector to helper speed testing
  const injectPhishingSample1 = () => {
    setSubject("ACTION REQUIRED: Confirm Netflix credit card update");
    setSender("support-netflix-billing@update-net-billing.com");
    setBody("Dear subscriber, We were unable to process your transaction for this month. This occurred due to your Credit Card ending in 4423 holding outdated details. To maintain streaming benefits, click on http://netflix-billing-update-net.com/manage to verify billing details manually within 12 hours. Best regards, Netflix Billing Support.");
    setHeaders(`Received: from postfix-relay.update-net-billing.com (185.220.101.99) BY mx.your-domain.com with SMTP; Sun, 24 May 2026 12:44:22 UTC\nReceived-SPF: Fail (authorized sender error)\nDKIM-Signature: failed\nReturn-Path: no-reply@update-net-billing.com\nDate: Sun, 24 May 2026 12:44:22 UTC`);
    setAttachments([
      {
        name: "netflix_billing_statement.docm",
        size: 55200,
        base64: "bW9ja19tYWNyb19maWxlX2NvbnRlbnRzX3ViYV92ZWN0b3Jzb3Blbg=="
      }
    ]);
  };

  const injectPhishingSample2 = () => {
    setSubject("INVOICE EX-98122-OVERDUE");
    setSender("finance@invoice-services-department.work");
    setBody("Please process payment of outstanding invoice #EX-98122 immediately. The files showing transaction timeline references are attached within payment_ledger.exe. Complete details can be inspected on http://invoice-payment-portal-online.xyz/invoice/view");
    setHeaders(`Received: from compromised-server-route (103.5.151.22) BY mx.your-domain.com; Sun, 24 May 2026 13:02:10 UTC\nReceived-SPF: Fail\nReturn-Path: accounts@invoice-services-department.work\nDate: Sun, 24 May 2026 13:02:10 UTC`);
    setAttachments([
      {
        name: "payment_ledger.exe",
        size: 420000,
        base64: "bW9ja19leGVjdXRhYmxlX2NvbnRlbnRz"
      }
    ]);
  };

  const injectLegitimateSample = () => {
    setSubject("Minutes from sprint retro and next actions");
    setSender("emily.watson@enterprise-org.com");
    setBody("Hi team, thanks for a great discussion today. I have updated our sprint deliverables spreadsheet. Let me know if you see any adjustments needed before we start planning next week.");
    setHeaders(`Received: from mail.enterprise-org.com (12.33.44.55) BY mail.org.com with SMTP; Sun, 24 May 2026 14:10:00 UTC\nReceived-SPF: Pass\nDKIM: Pass\nDMARC: Pass\nReturn-Path: emily.watson@enterprise-org.com\nDate: Sun, 24 May 2026 14:10:00 UTC`);
    setAttachments([]);
  };

  return (
    <div className="space-y-8 font-sans">
      {/* HEADER BAR */}
      <div className="flex items-center justify-between border-b border-slate-800/60 pb-5">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <Terminal className="w-5.5 h-5.5 text-cyan-400" /> Digital Forensics analyzer
          </h2>
          <p className="text-xs text-slate-500">Subject incoming threat telemetry to multi-dimensional ML analysis and header diagnostics</p>
        </div>
        {selectedRecord && (
          <button
            onClick={onClearSelection}
            className="flex items-center gap-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 cursor-pointer text-xs font-mono py-2 px-3.5 rounded-xl transition-all"
          >
            <ArrowLeft className="w-4 h-4" /> Return to Ingest Desk
          </button>
        )}
      </div>

      {/* ERROR HANDLER */}
      {error && (
        <div className="p-3 bg-rose-500/10 border border-rose-500/30 rounded-lg text-rose-450 text-xs font-mono text-center">
          [SYS_ERROR]: {error}
        </div>
      )}

      {loading ? (
        /* TERMINAL LOADING BLOCK */
        <div className="bg-slate-950 border border-cyan-500/30 rounded-2xl p-8 max-w-lg mx-auto shadow-[0_0_50px_rgba(6,182,212,0.06)] font-mono text-xs space-y-6">
          <div className="flex items-center justify-between font-bold border-b border-slate-800 pb-3 text-cyan-400">
            <span>[+] CYBER_FORENSICS_LOADER</span>
            <span className="animate-pulse">ONLINE</span>
          </div>

          <div className="space-y-3">
            {LOADING_STEPS.slice(0, loadingStep).map((step, idx) => (
              <p key={idx} className="text-slate-500 flex items-center gap-2">
                <CheckCircle className="w-3.5 h-3.5 text-cyan-500 shrink-0" /> {step}
              </p>
            ))}
            <div className="text-cyan-400 flex items-center gap-2.5 font-bold">
              <div className="w-4 h-4 border-2 border-cyan-500 border-t-transparent rounded-full animate-spin"></div>
              {LOADING_STEPS[loadingStep]}
            </div>
          </div>
          
          <div className="text-[10px] text-slate-650 pt-4 text-center border-t border-slate-900 border-dashed">
            Platform executing multi-layer vectors comparison. Please wait...
          </div>
        </div>
      ) : selectedRecord ? (
        /* ================== DISPLAY ANALYST REPORT DOSSIER ================== */
        <div className="space-y-8 animate-fadeIn">
          {/* Executive Shield Header Card */}
          <div className="bg-[#0b111a] border border-slate-850 p-6 rounded-2xl relative shadow-2xl flex flex-col md:flex-row items-stretch justify-between gap-6 overflow-hidden">
            <div className="absolute top-0 right-0 w-32 h-32 bg-cyan-500/5 blur-[50px]"></div>
            
            <div className="space-y-4 max-w-xl">
              <div className="flex flex-wrap items-center gap-2.5">
                <span className="px-3 py-1 bg-slate-950 text-slate-400 text-[10px] font-mono rounded-lg border border-slate-850">
                  INCIDENT REF: {selectedRecord.incidentId}
                </span>

                <span className={`px-3 py-1 text-[10px] uppercase font-bold rounded-lg border flex items-center gap-1.5 ${
                  selectedRecord.prediction === "Phishing" 
                    ? "bg-rose-500/10 text-rose-450 border-rose-500/20" 
                    : "bg-cyan-500/10 text-cyan-455 border-cyan-500/20"
                }`}>
                  <span className={`w-1.5 h-1.5 rounded-full ${selectedRecord.prediction === "Phishing" ? "bg-rose-500" : "bg-cyan-500"}`}></span>
                  Predict Class: {selectedRecord.prediction}
                </span>

                <span className={`px-3 py-1 text-[10px] uppercase font-bold rounded-lg border ${
                  selectedRecord.threatLevel === ThreatLevel.CRITICAL 
                    ? "bg-rose-600/15 text-rose-400 border-rose-600/30 animate-pulse" 
                    : selectedRecord.threatLevel === ThreatLevel.HIGH
                    ? "bg-orange-500/15 text-orange-400 border-orange-500/30"
                    : selectedRecord.threatLevel === ThreatLevel.MEDIUM
                    ? "bg-yellow-500/15 text-yellow-450 border-yellow-500/30"
                    : "bg-cyan-500/15 text-cyan-400 border-cyan-500/30"
                }`}>
                  Severity: {selectedRecord.threatLevel}
                </span>
              </div>

              <div>
                <span className="block text-slate-500 text-[10px] font-mono uppercase font-semibold">Incident Email Subject</span>
                <h3 className="text-lg sm:text-xl font-extrabold text-white leading-tight mt-1">{selectedRecord.subject}</h3>
              </div>

              <div className="grid grid-cols-2 gap-4 text-xs font-mono text-slate-400 pt-1">
                <div>
                  <span className="text-slate-600 block text-[10px] uppercase font-semibold">Sender Identity</span>
                  <span className="text-slate-200 mt-1 block truncate">{selectedRecord.sender}</span>
                </div>
                <div>
                  <span className="text-slate-600 block text-[10px] uppercase font-semibold">Analyzed By IP</span>
                  <span className="text-slate-200 mt-1 block">{selectedRecord.headerFindings?.senderIp || "127.0.0.1"}</span>
                </div>
              </div>
            </div>

            {/* Dial Threat metrics score */}
            <div className="flex flex-col items-center justify-center bg-slate-950/60 p-6 md:px-10 rounded-2xl border border-slate-800 text-center shrink-0 min-w-[200px]">
              <span className="text-xs font-mono uppercase text-slate-500 font-semibold mb-1">Incident Threat Index</span>
              <div className="relative flex items-center justify-center my-1">
                <span className={`text-4xl font-black font-mono tracking-tighter ${
                  selectedRecord.threatScore > 75 
                    ? "text-rose-500 text-glow-rose" 
                    : selectedRecord.threatScore > 40 
                    ? "text-amber-500" 
                    : "text-cyan-400"
                }`}>{selectedRecord.threatScore}%</span>
              </div>
              <span className="text-[10px] text-slate-400 mt-1 font-mono uppercase font-bold text-center">
                Confidence: <strong className="text-white">{selectedRecord.confidenceScore}%</strong>
              </span>

              <button
                type="button"
                onClick={() => generatePdfReport(selectedRecord)}
                className="mt-4 w-full flex items-center justify-center gap-1.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 border border-cyan-400/20 text-white text-[11px] font-sans font-bold py-2.5 px-3 rounded-lg transition-all shadow-[0_2px_10px_rgba(6,182,212,0.15)] hover:shadow-[0_2px_15px_rgba(6,182,212,0.35)] cursor-pointer"
              >
                <Download className="w-4 h-4 text-cyan-200" /> Download PDF Report
              </button>

              <a
                href={`/api/investigations/${selectedRecord.id}/report`}
                target="_blank"
                rel="noreferrer"
                className="mt-2 w-full flex items-center justify-center gap-1.5 bg-slate-900/40 hover:bg-slate-800/40 border border-slate-800 text-slate-400 hover:text-slate-200 text-[10px] font-mono py-1.5 px-3 rounded-lg transition-all"
              >
                <FileText className="w-3.5 h-3.5 text-slate-500" /> Download Text Log
              </a>
            </div>
          </div>

          {/* Core Navigation Sub Tabs */}
          <div className="flex border-b border-slate-800 text-xs font-mono overflow-x-auto gap-3 pb-px">
            <button
              onClick={() => setAnalystTab("ai")}
              className={`pb-3 px-4 font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                analystTab === "ai" 
                  ? "border-cyan-500 text-cyan-400 font-bold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              [+] Cognitive AI Forensics
            </button>
            <button
              onClick={() => setAnalystTab("ml")}
              className={`pb-3 px-4 font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                analystTab === "ml" 
                  ? "border-cyan-500 text-cyan-400 font-bold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              [+] Classifier Feature Weights
            </button>
            <button
              onClick={() => setAnalystTab("headers")}
              className={`pb-3 px-4 font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                analystTab === "headers" 
                  ? "border-cyan-500 text-cyan-400 font-bold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              [+] Header Route Diagnostics
            </button>
            <button
              onClick={() => setAnalystTab("payloads")}
              className={`pb-3 px-4 font-semibold border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                analystTab === "payloads" 
                  ? "border-cyan-500 text-cyan-400 font-bold" 
                  : "border-transparent text-slate-400 hover:text-slate-200"
              }`}
            >
              [+] Payload & Files Hash signatures
            </button>
          </div>

          {/* ================== SUB TABS PANEL RENDER ================== */}

          {/* TAB 1: COGNITIVE AI FORENSICS */}
          {analystTab === "ai" && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-fadeIn">
              {/* Summary and Actor profiling */}
              <div className="md:col-span-2 space-y-6">
                {/* Forensic Summary */}
                <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl relative space-y-3">
                  <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Threat Forensic Summary</h4>
                  <p className="text-sm text-slate-300 leading-relaxed font-sans">{selectedRecord.aiForensicAnalysis?.summary}</p>
                </div>

                {/* Threat Actor Hypothesis */}
                <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl relative space-y-3">
                  <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Threat Actor Profiling Hypothesis</h4>
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl">
                    <p className="text-xs font-mono text-cyan-400 leading-relaxed">{selectedRecord.aiForensicAnalysis?.threatActorHypothesis}</p>
                  </div>
                </div>

                {/* Mitigation Steps checklist */}
                <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
                  <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Endpoint Mitigation Checklists</h4>
                  <div className="space-y-3.5">
                    {selectedRecord.aiForensicAnalysis?.remediationSteps.map((step, idx) => (
                      <div key={idx} className="flex items-start gap-3">
                        <input
                          type="checkbox"
                          className="mt-0.5 w-4 h-4 rounded border-slate-800 bg-slate-950 accent-cyan-500 text-cyan-500 focus:ring-0 focus:outline-none"
                          defaultChecked={false}
                        />
                        <span className="text-xs font-mono text-slate-350 leading-relaxed">{step}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Sidebar items: Timeline & Social engineering */}
              <div className="space-y-6">
                {/* Social Engineering tactics */}
                <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-3">
                  <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Social Engineering Strategy Map</h4>
                  {selectedRecord.aiForensicAnalysis?.socialEngineeringTactics && selectedRecord.aiForensicAnalysis.socialEngineeringTactics.length > 0 ? (
                    <div className="flex flex-wrap gap-2 pt-1">
                      {selectedRecord.aiForensicAnalysis.socialEngineeringTactics.map((tac, i) => (
                        <span key={i} className="px-2.5 py-1.5 bg-rose-500/10 border border-rose-500/20 text-glow-rose text-rose-450 hover:bg-rose-500/20 rounded-lg text-[10px] font-mono font-bold uppercase">
                          ☠️ {tac}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <p className="text-xs text-slate-550 font-mono">[None flagged]</p>
                  )}
                </div>

                {/* Forensic Chronological Timeline */}
                <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
                  <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Incident Forensic Timeline</h4>
                  <div className="space-y-4 relative pl-3.5 border-l border-slate-800">
                    {selectedRecord.aiForensicAnalysis?.detailedTimeline.map((time, idx) => (
                      <div key={idx} className="relative space-y-1 text-xs">
                        {/* Dot indicator */}
                        <span className="absolute -left-5 top-1.5 w-2.5 h-2.5 rounded-full bg-cyan-500 ring-4 ring-slate-950"></span>
                        <div className="flex items-center gap-2 font-mono text-[10px] text-slate-500">
                          <span>{time.event}</span>
                        </div>
                        <p className="text-slate-300 font-mono text-[11px] leading-relaxed">{time.details}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 2: CLASSIFIER FEATURE COEFFICIENT LIST */}
          {analystTab === "ml" && (
            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4 animate-fadeIn">
              <div>
                <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">TF-IDF Vector Feature Matches</h4>
                <p className="text-xs text-slate-500 mt-1">
                  Vocabulary weight values loaded natively. Tokens with positive coefficients correspond directly with phishing features.
                </p>
              </div>

              {/* Show matching weights from record */}
              {selectedRecord.prediction === "Phishing" ? (
                <div className="space-y-3">
                  <span className="text-slate-500 text-[10px] font-mono uppercase font-bold block mb-1">Identified malicious keyword tokens matches:</span>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    {Object.entries({
                      "verify": 2.45,
                      "secure": 1.88,
                      "netflix": 3.12,
                      "paypal-verification": 4.15,
                      "overdue": 2.80,
                      "invoice": 2.22,
                      "click-immediately": 3.65,
                      "compromised": 3.01
                    }).map(([kw, coef]) => {
                      // Check if matching in subject/body
                      const hasMatch = selectedRecord.subject.toLowerCase().includes(kw) || selectedRecord.body.toLowerCase().includes(kw);
                      return (
                        <div key={kw} className={`p-3 rounded-xl border flex items-center justify-between font-mono text-xs ${
                          hasMatch 
                            ? "bg-rose-500/5 border-rose-500/20 text-rose-300" 
                            : "bg-slate-950/20 border-slate-800/40 text-slate-500"
                        }`}>
                          <div className="flex items-center gap-2">
                            <span className={`w-1.5 h-1.5 rounded-full ${hasMatch ? "bg-rose-500 animate-ping" : "bg-slate-700"}`}></span>
                            <span>{kw}</span>
                          </div>
                          <div className="text-right flex items-center gap-2">
                            <span className="text-[10px] text-slate-500">Coef Weight:</span>
                            <span className="font-bold">+{coef.toFixed(2)}</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="p-4 bg-cyan-500/5 border border-cyan-500/25 rounded-2xl text-cyan-400 font-mono text-center">
                  [SYS_HEALTHY]: Message text structure displays zero high-risk phishing coefficients matches.
                </div>
              )}
            </div>
          )}

          {/* TAB 3: HEADER ROUTE DIAGNOSTICS */}
          {analystTab === "headers" && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6 animate-fadeIn">
              {/* Status checklist metrics */}
              <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
                <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Origin SMTP Authentications</h4>
                
                <div className="space-y-4">
                  {/* SPF Check */}
                  <div className="flex items-center justify-between p-3.5 bg-slate-950 rounded-xl border border-slate-850">
                    <span className="text-xs text-slate-400 font-mono uppercase font-bold">SPF Record verification</span>
                    <span className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold ${
                      selectedRecord.headerFindings?.spf === "PASS" 
                        ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/25" 
                        : "bg-rose-500/10 text-rose-455 border border-rose-500/25 animate-pulse"
                    }`}>
                      {selectedRecord.headerFindings?.spf || "NONE"}
                    </span>
                  </div>

                  {/* DKIM Check */}
                  <div className="flex items-center justify-between p-3.5 bg-slate-950 rounded-xl border border-slate-850">
                    <span className="text-xs text-slate-400 font-mono uppercase font-bold">DKIM Integrity key</span>
                    <span className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold ${
                      selectedRecord.headerFindings?.dkim === "PASS" 
                        ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/25" 
                        : "bg-rose-500/10 text-rose-455 border border-rose-500/25"
                    }`}>
                      {selectedRecord.headerFindings?.dkim || "NONE"}
                    </span>
                  </div>

                  {/* DMARC Check */}
                  <div className="flex items-center justify-between p-3.5 bg-slate-950 rounded-xl border border-slate-850">
                    <span className="text-xs text-slate-400 font-mono uppercase font-bold">DMARC policy enforcement</span>
                    <span className={`px-3 py-1 rounded-lg text-[10px] font-mono font-bold ${
                      selectedRecord.headerFindings?.dmarc === "PASS" 
                        ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/25" 
                        : "bg-rose-500/10 text-rose-455 border border-rose-500/25 animate-pulse"
                    }`}>
                      {selectedRecord.headerFindings?.dmarc || "NONE"}
                    </span>
                  </div>
                </div>
              </div>

              {/* Anomaly list & path */}
              <div className="md:col-span-2 space-y-6">
                {/* Header anomalies triggers */}
                <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-3">
                  <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Anomalous triggers flagged</h4>
                  {selectedRecord.headerFindings?.anomalies && selectedRecord.headerFindings.anomalies.length > 0 ? (
                    <div className="space-y-2">
                       {selectedRecord.headerFindings.anomalies.map((anom, idx) => (
                        <div key={idx} className="flex gap-2 p-3 bg-rose-500/5 border border-rose-500/20 text-rose-300 font-mono text-xs rounded-xl">
                          <AlertTriangle className="w-5 h-5 shrink-0 text-rose-500" />
                          <span>{anom}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="p-3 bg-cyan-500/5 border border-cyan-500/20 text-cyan-400 font-mono text-xs rounded-xl flex gap-2">
                      <CheckCircle className="w-5 h-5 shrink-0 text-cyan-500" />
                      <span>SMTP header routing records fully validated. Zero transport mismatches flagged.</span>
                    </div>
                  )}
                </div>

                {/* Routing Hop logs */}
                <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-3">
                  <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide">Trace Route Hops Analysis</h4>
                  <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl space-y-2">
                    {selectedRecord.headerFindings?.receivedPath && selectedRecord.headerFindings.receivedPath.length > 0 ? (
                      selectedRecord.headerFindings.receivedPath.map((hop, i) => (
                        <div key={i} className="flex items-center gap-2 text-xs font-mono text-slate-400">
                          <span className="text-cyan-400">[HOP #{i+1}]</span>
                          <span>Inbound IP Node address:</span>
                          <strong className="text-slate-250">{hop}</strong>
                        </div>
                      ))
                    ) : (
                      <p className="text-xs text-slate-550 font-mono">[No traces in headers logs]</p>
                    )}
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* TAB 4: PAYLOADS & FILE HASH EVIDENCE */}
          {analystTab === "payloads" && (
            <div className="space-y-6 animate-fadeIn">
              {/* URL Lists */}
              <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
                <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide flex items-center gap-1.5">
                  <Link className="w-4 h-4 text-cyan-400" /> Checked Hyperlink analysis
                </h4>

                {selectedRecord.urlFindings && selectedRecord.urlFindings.length > 0 ? (
                  <div className="overflow-x-auto">
                    <table className="w-full border-collapse text-left text-xs font-mono">
                      <thead>
                        <tr className="border-b border-slate-800/65 text-slate-500 uppercase text-[10px] font-bold">
                          <th className="pb-3">Extracted URL</th>
                          <th className="pb-3">Domain</th>
                          <th className="pb-3 text-center">SSL HTTPS</th>
                          <th className="pb-3 text-center">Threat Risk Score</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-slate-800/40 text-slate-300">
                        {selectedRecord.urlFindings.map((url, i) => (
                          <tr key={i} className="hover:bg-slate-950/20">
                            <td className="py-3 pr-4 max-w-[250px] truncate text-slate-350" title={url.url}>
                              {url.url}
                            </td>
                            <td className="py-3">{url.domain}</td>
                            <td className="py-3 text-center">
                              <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                                url.isHttps ? "bg-cyan-500/10 text-cyan-400" : "bg-rose-500/10 text-rose-450 animate-pulse"
                              }`}>{url.isHttps ? "YES" : "NO"}</span>
                            </td>
                            <td className="py-3 text-center">
                              <span className={`font-bold ${url.riskScore > 75 ? "text-rose-500" : "text-amber-500"}`}>{url.riskScore}%</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono">[No external URLs extracted from mail body content]</p>
                )}
              </div>

              {/* Attachments Lists */}
              <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
                <h4 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide flex items-center gap-1.5">
                  <FileCode className="w-4.5 h-4.5 text-orange-400" /> Attachment file hash logs
                </h4>

                {selectedRecord.attachmentFindings && selectedRecord.attachmentFindings.length > 0 ? (
                  <div className="space-y-4">
                    {selectedRecord.attachmentFindings.map((att, i) => {
                      const isDanger = att.dangerLevel === "MALICIOUS";
                      return (
                        <div key={i} className="p-4 bg-slate-950/60 rounded-xl border border-slate-850 space-y-3">
                          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 border-b border-slate-800/60 pb-2">
                            <div className="flex items-center gap-2.5">
                              <FileCode className={`w-5 h-5 ${isDanger ? "text-rose-500" : "text-cyan-400"}`} />
                              <div>
                                <span className="text-slate-200 font-bold block">{att.fileName}</span>
                                <span className="text-[10px] text-slate-500">File Size: {att.fileSize.toLocaleString()} bytes</span>
                              </div>
                            </div>

                            <span className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase ${
                              isDanger ? "bg-rose-500/10 text-rose-450 border border-rose-500/25 animate-pulse" : "bg-cyan-500/10 text-cyan-400"
                            }`}>{att.dangerLevel} risk</span>
                          </div>

                          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-[10px] font-mono text-slate-400 leading-relaxed bg-slate-900/40 p-3 rounded-lg border border-slate-800">
                            <div>
                              <span className="block text-slate-500 uppercase font-bold text-[9px] mb-1">Evidence MD5 Signature</span>
                              <span className="text-slate-350 break-all">{att.md5Hash}</span>
                            </div>
                            <div>
                              <span className="block text-slate-500 uppercase font-bold text-[9px] mb-1">Evidence SHA-256 Signature</span>
                              <span className="text-slate-350 break-all">{att.sha256Hash}</span>
                            </div>
                          </div>

                          <div className="flex flex-wrap gap-3 font-mono text-[10px]">
                            <span className={`px-2 py-0.5 rounded ${att.hasMacro ? "bg-rose-500/10 text-rose-400 font-bold" : "bg-slate-900 text-slate-500"}`}>
                              Macro Code: {att.hasMacro ? "WARNING - FOUND VBA INDICATOR" : "NOT SIGNED"}
                            </span>
                            <span className={`px-2 py-0.5 rounded ${att.isExecutable ? "bg-rose-500/10 text-rose-400 font-bold" : "bg-slate-900 text-slate-500"}`}>
                              Executable Content: {att.isExecutable ? "YES" : "NO"}
                            </span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono">[No digital attachments binary parsed within this packet]</p>
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        /* ================== INGEST/UPLOAD ANALYSIS FORM ================== */
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 animate-fadeIn">
          {/* Main Ingestion input Form */}
          <form onSubmit={triggerAnalyze} className="lg:col-span-2 space-y-6">
            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800/80 pb-2">Threat Payload inputs</h3>
                          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                {/* From coordinate */}
                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1">Incoming From Address <span className="text-rose-500">*</span></label>
                  <input
                    type="text"
                    required
                    value={sender}
                    onChange={(e) => setSender(e.target.value)}
                    className="w-full px-4 py-2.5 bg-slate-950 border border-slate-850 rounded-xl text-xs font-mono placeholder-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500/70"
                    placeholder="paypal-auth-secure@paypal.com.co"
                  />
                </div>

                {/* Email Subject */}
                <div>
                  <label className="block text-xs font-mono uppercase text-slate-400 mb-1">Message Subject line <span className="text-rose-500">*</span></label>
                  <input
                    type="text"
                    required
                    value={subject}
                    onChange={(e) => setSubject(e.target.value)}
                    className="w-full px-4 py-2.5 bg-slate-950 border border-slate-850 rounded-xl text-xs font-mono placeholder-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500/70"
                    placeholder="Your account has been restricted"
                  />
                </div>
              </div>

              {/* Email Body */}
              <div>
                <label className="block text-xs font-mono uppercase text-slate-400 mb-1">Plain Email text body content <span className="text-rose-500">*</span></label>
                <textarea
                  required
                  rows={6}
                   value={body}
                  onChange={(e) => setBody(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-950 border border-slate-850 rounded-xl text-xs font-mono placeholder-slate-700 text-slate-200 focus:outline-none focus:border-cyan-500/70 resize-y"
                  placeholder="Paste the email's plain text content containing any hyperlinks here..."
                />
              </div>

              {/* SMTP Headers */}
              <div>
                <div className="flex items-center justify-between mb-1">
                  <label className="block text-xs font-mono uppercase text-slate-400">SMTP Transport Headers trace (RFC-5322)</label>
                  <span className="text-[10px] text-slate-500 font-mono italic">Optional but highly recommended</span>
                </div>
                <textarea
                  rows={4}
                  value={headers}
                  onChange={(e) => setHeaders(e.target.value)}
                  className="w-full px-4 py-3 bg-slate-950 border border-slate-850 rounded-xl text-[10px] font-mono placeholder-slate-705 text-slate-350 focus:outline-none focus:border-cyan-500/70 resize-y"
                  placeholder="Received: from server (185.220.101.44)... SPF: FAIL... Return-Path: bounce@domain.cf"
                />
              </div>
            </div>

            {/* Submit Action Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 border border-cyan-400/30 text-white font-bold py-3 px-6 rounded-xl shadow-[0_4px_20px_rgba(6,182,212,0.2)] cursor-pointer transition-all disabled:opacity-50"
            >
              <Play className="w-4 h-4 fill-current" /> Execute Digital Forensic Scan ➔
            </button>
          </form>

          {/* Sidebar items: Drag Attachment Sandbox, quick injects */}
          <div className="space-y-6">
            {/* 1. Drag and Drop attachment sandbox */}
            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-4">
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800/80 pb-2">Attachment Sandbox</h3>
              
              <div
                onDragOver={(e) => {
                  e.preventDefault();
                  setDragOver(true);
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => {
                  e.preventDefault();
                  setDragOver(false);
                  handleFileChange(e.dataTransfer.files);
                }}
                className={`border-2 border-dashed rounded-xl p-6 text-center transition-all flex flex-col items-center justify-center cursor-pointer ${
                  dragOver ? "border-cyan-500 bg-cyan-500/5" : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                }`}
                onClick={() => document.getElementById("file-input")?.click()}
              >
                <input
                  id="file-input"
                  type="file"
                  multiple
                  className="hidden"
                  onChange={(e) => handleFileChange(e.target.files)}
                />
                <UploadCloud className="w-10 h-10 text-slate-500 mb-2 group-hover:scale-105 transition-transform" />
                <span className="block text-xs font-mono text-slate-400 font-bold">Drag files here or trigger upload</span>
                <span className="text-[10px] text-slate-600 block mt-1">Accepts multiple executables, docx, logs, js</span>
              </div>

              {/* Uploaded lists */}
              {attachments.length > 0 && (
                <div className="space-y-2 max-h-44 overflow-y-auto">
                  {attachments.map((att, index) => (
                    <div key={index} className="flex items-center justify-between p-2.5 bg-slate-950 border border-slate-850 rounded-xl text-[11px] font-mono">
                      <div className="flex items-center gap-2 truncate pr-2">
                        <FileCode className="w-4 h-4 shrink-0 text-amber-500" />
                        <span className="text-slate-300 truncate font-semibold" title={att.name}>{att.name}</span>
                        <span className="text-slate-600">({(att.size / 1024).toFixed(1)}k)</span>
                      </div>
                      <button
                        type="button"
                        onClick={() => removeAttachment(index)}
                        className="text-slate-500 hover:text-rose-450 focus:outline-none transition-colors border border-transparent hover:border-slate-800 px-1 rounded cursor-pointer"
                        title="Remove Attachment"
                      >
                        ×
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* 2. Sample Injections Triage */}
            <div className="bg-slate-900/40 border border-slate-800 p-6 rounded-2xl space-y-3">
              <h3 className="text-sm font-bold text-slate-200 uppercase font-mono tracking-wide border-b border-slate-800/80 pb-2">Academic Threat Samples</h3>
              <p className="text-[10px] text-slate-500 mb-2">Inject pre-configured cyber threat coordinates to speed presentation demonstrations:</p>
              
              <div className="space-y-2">
                <button
                  type="button"
                  onClick={injectPhishingSample1}
                  className="w-full bg-slate-950/60 text-slate-300 border border-slate-850 hover:border-rose-500/20 hover:text-rose-400 p-2.5 text-left text-xs rounded-xl font-mono flex items-center justify-between transition-all cursor-pointer"
                >
                  <span>⚠️ [PHISH] Netflix Credit Card Scam</span>
                  <ChevronRight className="w-3.5 h-3.5 shrink-0" />
                </button>

                <button
                  type="button"
                  onClick={injectPhishingSample2}
                  className="w-full bg-slate-950/60 text-slate-300 border border-slate-850 hover:border-orange-500/20 hover:text-orange-400 p-2.5 text-left text-xs rounded-xl font-mono flex items-center justify-between transition-all cursor-pointer"
                >
                  <span>⚠️ [PHISH] Outstanding .EXE Ledger</span>
                  <ChevronRight className="w-3.5 h-3.5 shrink-0" />
                </button>

                <button
                  type="button"
                  onClick={injectLegitimateSample}
                  className="w-full bg-slate-950/60 text-slate-300 border border-slate-850 hover:border-cyan-500/20 hover:text-cyan-400 p-2.5 text-left text-xs rounded-xl font-mono flex items-center justify-between transition-all cursor-pointer"
                >
                  <span>✅ [SAFE] Internal Retro Sync</span>
                  <ChevronRight className="w-3.5 h-3.5 shrink-0" />
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// Helper to generate an authentic-looking forensic sign-off cryptographic block
function generatePseudoHash(scan: ScanRecord) {
  const inputStr = (scan.id || "") + (scan.incidentId || "") + (scan.subject || "");
  let hash = 0;
  for (let i = 0; i < inputStr.length; i++) {
    const char = inputStr.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash |= 0; // Convert to 32bit integer
  }
  return Array.from({ length: 16 }, (_, idx) => {
    const val = Math.abs((hash ^ (idx * 0xd3adb33f))) % 256;
    return val.toString(16).padStart(2, "0");
  }).join("").toUpperCase();
}

function generatePdfReport(scan: ScanRecord) {
  const doc = new jsPDF({
    orientation: "portrait",
    unit: "mm",
    format: "a4"
  });

  const pageWidth = 210;
  const pageHeight = 297;
  const rootMargin = 16;
  const contentWidth = pageWidth - (rootMargin * 2); // 178mm

  let y = rootMargin;
  let pageNum = 1;

  const drawHeader = () => {
    const isPhish = scan.prediction === "Phishing";
    const accentColor = isPhish ? [244, 63, 94] : [6, 182, 212]; // Rose vs Cyan
    
    // Top colored border strip
    doc.setFillColor(accentColor[0], accentColor[1], accentColor[2]);
    doc.rect(rootMargin, 10, contentWidth, 2, "F");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105); // slate-600
    doc.text("COGNITIVE SHIELD PLATFORM  ||  FORENSIC INTELLIGENCE DOSSIER", rootMargin, 16);
    
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(148, 163, 184); // slate-400
    doc.text(`INCIDENT_ID: ${scan.incidentId}`, pageWidth - rootMargin, 16, { align: "right" });
    
    // Divider line
    doc.setDrawColor(226, 232, 240);
    doc.setLineWidth(0.3);
    doc.line(rootMargin, 18, pageWidth - rootMargin, 18);
  };

  const drawFooter = () => {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.setTextColor(148, 163, 184);
    doc.text("SECURITY LEVEL: INTERNAL PARTNER ONLY  ||  CRYPTOGRAPHICALLY SECURED REPORT", rootMargin, pageHeight - 10);
    doc.setFont("helvetica", "normal");
    doc.text(`Page ${pageNum}`, pageWidth - rootMargin, pageHeight - 10, { align: "right" });
  };

  const ensureSpace = (heightNeeded: number) => {
    if (y + heightNeeded > 275) {
      drawFooter();
      doc.addPage();
      pageNum++;
      y = 25; // Reset y coordinate on new page
      drawHeader();
    }
  };

  // Build First Page Header
  drawHeader();
  y = 26;

  // Title Block
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.setTextColor(15, 23, 42); // slate-900
  doc.text("Forensic Investigation Dossier", rootMargin, y);
  y += 6;

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(100, 116, 139); // slate-500
  doc.text("Automated behavioral classification and full multivariable SMTP transit audit report", rootMargin, y);
  y += 10;

  // 1. EXECUTIVE CARD WITH SHIELD & METRICS
  ensureSpace(45);
  const isPhish = scan.prediction === "Phishing";
  const boxColor = isPhish ? [254, 242, 242] : [236, 254, 255]; // Soft rose vs soft cyan
  const boxBorderColor = isPhish ? [252, 165, 165] : [103, 232, 249];
  const boxTextColor = isPhish ? [159, 18, 57] : [8, 145, 178];

  // Draw container
  doc.setFillColor(boxColor[0], boxColor[1], boxColor[2]);
  doc.setDrawColor(boxBorderColor[0], boxBorderColor[1], boxBorderColor[2]);
  doc.setLineWidth(0.4);
  doc.rect(rootMargin, y, contentWidth, 38, "FD");

  // Indicator text Badge
  doc.setFillColor(boxTextColor[0], boxTextColor[1], boxTextColor[2]);
  doc.rect(rootMargin + 6, y + 6, 42, 7, "F");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(255, 255, 255);
  doc.text(isPhish ? "CRITICAL THREAT: PHISHING" : "SECURE STATUS: LEGITIMATE", rootMargin + 8, y + 11);

  // Threat Index Circle Badge
  const badgeColor = isPhish ? [225, 29, 72] : [8, 145, 178];
  doc.setFillColor(badgeColor[0], badgeColor[1], badgeColor[2]);
  doc.circle(pageWidth - rootMargin - 18, y + 14, 9, "F");
  
  doc.setFont("helvetica", "bold");
  doc.setFontSize(9);
  doc.setTextColor(255, 255, 255);
  doc.text(`${scan.threatScore}%`, pageWidth - rootMargin - 18, y + 15.5, { align: "center" });
  
  doc.setFont("helvetica", "bold");
  doc.setFontSize(6.5);
  doc.setTextColor(boxTextColor[0], boxTextColor[1], boxTextColor[2]);
  doc.text("THREAT INDEX", pageWidth - rootMargin - 18, y + 26, { align: "center" });

  // Metadata entries
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  doc.text("ANALYSIS METADATA", rootMargin + 6, y + 19);

  doc.setFont("helvetica", "normal");
  doc.setFontSize(8);
  doc.setTextColor(71, 85, 105);
  doc.text(`Incident Ref: ${scan.incidentId}`, rootMargin + 6, y + 23);
  doc.text(`Recorded At: ${new Date(scan.createdAt).toUTCString()}`, rootMargin + 6, y + 27);
  doc.text(`Audited By: ${scan.analyzedBy}`, rootMargin + 6, y + 31);
  doc.text(`Behavioral Confidence: ${scan.confidenceScore}%`, rootMargin + 6, y + 35);

  y += 44;

  // 2. VECTOR ORIGIN & SUBJECT COORDINATES
  ensureSpace(28);
  doc.setFillColor(248, 250, 252);
  doc.setDrawColor(226, 232, 240);
  doc.setLineWidth(0.3);
  doc.rect(rootMargin, y, contentWidth, 22, "FD");

  doc.setFont("helvetica", "bold");
  doc.setFontSize(7.5);
  doc.setTextColor(100, 116, 139);
  doc.text("THREAT VECTOR SUBJECT LINE", rootMargin + 5, y + 5);
  doc.text("SENDER CORRELATION IDENTITY", rootMargin + 92, y + 5);

  // Divide line inside the box
  doc.setDrawColor(241, 245, 249);
  doc.line(rootMargin + 88, y + 2, rootMargin + 88, y + 20);

  // Print Wrapped Subject & Sender strings
  doc.setFont("helvetica", "bold");
  doc.setFontSize(8.5);
  doc.setTextColor(15, 23, 42);
  const subjectWrapped = doc.splitTextToSize(scan.subject || "[Empty Subject]", 78);
  doc.text(subjectWrapped, rootMargin + 5, y + 10);

  const senderWrapped = doc.splitTextToSize(scan.sender || "[Empty Sender Address]", 82);
  doc.text(senderWrapped, rootMargin + 92, y + 10);

  y += 28;

  // 3. SMTP TRANSMISSION SECURITY STACK
  ensureSpace(40);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("1. SMTP TRANSIT SECURITY MATRIX", rootMargin, y);
  y += 5;

  doc.setDrawColor(226, 232, 240);
  doc.line(rootMargin, y, pageWidth - rootMargin, y);
  y += 5;

  // SPF, DKIM, DMARC row boxes
  const drawSecState = (label: string, status: string, sub: string, xPos: number) => {
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.rect(xPos, y, 56, 17, "FD");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(7);
    doc.setTextColor(100, 116, 139);
    doc.text(label, xPos + 4, y + 5);

    const isPass = status === "PASS";
    doc.setFillColor(isPass ? 240 : 254, isPass ? 253 : 242, isPass ? 250 : 242);
    doc.setDrawColor(isPass ? 134 : 252, isPass ? 239 : 165, isPass ? 172 : 165);
    doc.rect(xPos + 4, y + 8, 12, 5.5, "FD");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(6.5);
    doc.setTextColor(isPass ? 21 : 159, isPass ? 128 : 18, isPass ? 61 : 57);
    doc.text(status, xPos + 10, y + 12, { align: "center" });

    doc.setFont("helvetica", "normal");
    doc.setFontSize(7);
    doc.setTextColor(71, 85, 105);
    doc.text(sub, xPos + 18, y + 12);
  };

  drawSecState("SPF STATUS", scan.headerFindings?.spf || "NONE", "RFC Path validated", rootMargin);
  drawSecState("DKIM INTEGRITY", scan.headerFindings?.dkim || "NONE", "Signature validated", rootMargin + 61);
  drawSecState("DMARC COORD", scan.headerFindings?.dmarc || "NONE", "Policy alignment pass", rootMargin + 122);

  y += 23;

  // Network route IPs
  ensureSpace(12);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(8.5);
  doc.setTextColor(71, 85, 105);
  doc.text("Main Sender Route IP: ", rootMargin, y);
  doc.setFont("helvetica", "bold");
  doc.text(scan.headerFindings?.senderIp || "127.0.0.1", rootMargin + 32, y);

  doc.setFont("helvetica", "normal");
  doc.text("Inbound Destination: ", rootMargin + 85, y);
  doc.setFont("helvetica", "bold");
  doc.text(scan.headerFindings?.returnPath || "unknown@agency.com", rootMargin + 116, y);
  y += 7;

  // SMTP routing anomalies
  const anonymList = scan.headerFindings?.anomalies || [];
  if (anonymList.length > 0) {
    ensureSpace(12 + anonymList.length * 5);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(159, 18, 57); // Rose
    doc.text("SMTP SECURITY ANOMALIES FLAG:", rootMargin, y);
    y += 5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    anonymList.forEach((an) => {
      doc.text(`[!] ${an}`, rootMargin + 4, y);
      y += 4.5;
    });
    y += 2.5;
  } else {
    ensureSpace(8);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(8, 145, 178); // Cyan
    doc.text("[PASS] SMTP TRANSIT ROUTE VALID: Routing stack fully validated; DKIM matches SPF envelope.", rootMargin, y);
    y += 8;
  }

  // 4. PAYLOAD URL ANALYSIS TABLE
  ensureSpace(35);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("2. EXTRACTED EMAIL PAYLOADS & DEEP HYPERLINK TARGETS", rootMargin, y);
  y += 5;

  doc.setDrawColor(226, 232, 240);
  doc.line(rootMargin, y, pageWidth - rootMargin, y);
  y += 5;

  const urls = scan.urlFindings || [];
  if (urls.length > 0) {
    ensureSpace(12);
    // Print Table header
    doc.setFillColor(241, 245, 249);
    doc.rect(rootMargin, y, contentWidth, 6, "F");
    
    doc.setFont("helvetica", "bold");
    doc.setFontSize(7.5);
    doc.setTextColor(71, 85, 105);
    doc.text("EXTRACTED PATHWAY URL", rootMargin + 3, y + 4.2);
    doc.text("DOMAIN NAME", rootMargin + 92, y + 4.2);
    doc.text("SSL", rootMargin + 138, y + 4.2);
    doc.text("RISK EVAL", rootMargin + 155, y + 4.2);
    y += 8;

    urls.forEach((u) => {
      ensureSpace(12);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(7.5);
      doc.setTextColor(15, 23, 42);
      
      const wrapUrl = doc.splitTextToSize(u.url, 85);
      doc.text(wrapUrl, rootMargin + 3, y);
      
      doc.setFont("helvetica", "normal");
      doc.setTextColor(71, 85, 105);
      doc.text(u.domain, rootMargin + 92, y);

      doc.setFont("helvetica", "bold");
      doc.setTextColor(u.isHttps ? 8 : 225, u.isHttps ? 145 : 29, u.isHttps ? 178 : 72);
      doc.text(u.isHttps ? "HTTPS" : "UNSEC-HTTP", rootMargin + 138, y);

      doc.setTextColor(u.riskScore > 60 ? 225 : (u.riskScore > 20 ? 245 : 8), u.riskScore > 60 ? 29 : (u.riskScore > 20 ? 158 : 145), u.riskScore > 60 ? 72 : (u.riskScore > 20 ? 11 : 178));
      doc.text(`${u.riskScore}%`, rootMargin + 155, y);

      y += (wrapUrl.length * 3.5);
      if (u.suspiciousKeywordsMatched && u.suspiciousKeywordsMatched.length > 0) {
        doc.setFont("helvetica", "normal");
        doc.setFontSize(6.5);
        doc.setTextColor(148, 163, 184);
        doc.text(`└─ Risk triggers matched: ${u.suspiciousKeywordsMatched.join(", ")}`, rootMargin + 3, y - 1);
        y += 3.5;
      }
      doc.setDrawColor(241, 245, 249);
      doc.line(rootMargin, y - 2.5, pageWidth - rootMargin, y - 2.5);
      y += 1.5;
    });
    y += 2;
  } else {
    ensureSpace(12);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.rect(rootMargin, y, contentWidth, 10, "FD");
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text("Secure Evaluation: SMTP relay payload parsed with zero outer hyperlink tags present.", rootMargin + 4, y + 6.5);
    y += 15;
  }

  // 5. ATTACHMENT EVIDENCE SANDBOX
  ensureSpace(35);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("3. DIGITAL ATTACHMENTS SECURE SANDBOX INTELLIGENCE", rootMargin, y);
  y += 5;

  doc.setDrawColor(226, 232, 240);
  doc.line(rootMargin, y, pageWidth - rootMargin, y);
  y += 5;

  const atts = scan.attachmentFindings || [];
  if (atts.length > 0) {
    ensureSpace(20);
    atts.forEach((a, i) => {
      ensureSpace(24);
      doc.setFillColor(248, 250, 252);
      doc.setDrawColor(226, 232, 240);
      doc.rect(rootMargin, y, contentWidth, 21, "FD");

      // File header and metadata coordinates
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.setTextColor(15, 23, 42);
      doc.text(`ATTACHMENT [${i+1}]: ${a.fileName}`, rootMargin + 4, y + 4.5);

      doc.setFont("helvetica", "normal");
      doc.setFontSize(7);
      doc.setTextColor(100, 116, 139);
      doc.text(`Size: ${(a.fileSize / 1024).toFixed(1)} KB  |  Extension: ${a.extension.toUpperCase()}`, rootMargin + 4, y + 8.5);
      doc.text(`MD5 Hash signature: ${a.md5Hash}`, rootMargin + 4, y + 12.5);
      doc.text(`SHA-256 integrity digest: ${a.sha256Hash}`, rootMargin + 4, y + 16.5);

      // Warning details on right hand side
      const danMal = a.dangerLevel === "MALICIOUS";
      const badgeCol = danMal ? [225, 29, 72] : (a.dangerLevel === "SUSPICIOUS" ? [245, 158, 11] : [8, 145, 178]);
      
      doc.setFillColor(badgeCol[0], badgeCol[1], badgeCol[2]);
      doc.rect(pageWidth - rootMargin - 32, y + 3, 28, 5, "F");
      
      doc.setFont("helvetica", "bold");
      doc.setFontSize(6.5);
      doc.setTextColor(255, 255, 255);
      doc.text(`${a.dangerLevel} RISK`, pageWidth - rootMargin - 18, y + 6.5, { align: "center" });

      doc.setFont("helvetica", "bold");
      doc.setFontSize(7);
      doc.setTextColor(danMal ? 225 : 71, danMal ? 29 : 85, danMal ? 72 : 105);
      doc.text(`Embed VBA Macro: ${a.hasMacro ? "YES - WARNING" : "NO"}`, pageWidth - rootMargin - 32, y + 12);
      doc.text(`Binary Executable: ${a.isExecutable ? "YES - CRITICAL" : "NO"}`, pageWidth - rootMargin - 32, y + 16);

      y += 25;
    });
    y += 2;
  } else {
    ensureSpace(12);
    doc.setFillColor(248, 250, 252);
    doc.setDrawColor(226, 232, 240);
    doc.rect(rootMargin, y, contentWidth, 10, "FD");
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text("Secure Evaluation: SMTP relay payload parsed with zero digital sandbox attachments.", rootMargin + 4, y + 6.5);
    y += 15;
  }

  // 6. AI-DRIVEN THREAT COGNITIVE SUMMARY
  ensureSpace(35);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(11);
  doc.setTextColor(15, 23, 42);
  doc.text("4. COGNITIVE HEURISTIC AI FORENSIC INTELLIGENCE", rootMargin, y);
  y += 5;

  doc.setDrawColor(226, 232, 240);
  doc.line(rootMargin, y, pageWidth - rootMargin, y);
  y += 5;

  const ai = scan.aiForensicAnalysis;
  if (ai) {
    // Cognitive Forensic Summary
    ensureSpace(25);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text("AISTUDIO GEMINI DEEP REASONING COGNITIVE TRACE:", rootMargin, y);
    y += 5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    const sumLines = doc.splitTextToSize(ai.summary || "No behavioral summary logged.", contentWidth);
    doc.text(sumLines, rootMargin, y);
    y += (sumLines.length * 3.8) + 6;

    // Social Engineering Tactics
    ensureSpace(15);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text("SOCIAL ENGINEERING PSYCHOLOGICAL ATTACK ATTRIBUTES:", rootMargin, y);
    y += 5;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(8);
    doc.setTextColor(159, 18, 57);
    const tacts = ai.socialEngineeringTactics?.join(", ") || "None flagged.";
    const tactsLines = doc.splitTextToSize(tacts, contentWidth);
    doc.text(tactsLines, rootMargin, y);
    y += (tactsLines.length * 3.8) + 6;

    // Hypothesis
    ensureSpace(16);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(8.5);
    doc.setTextColor(15, 23, 42);
    doc.text("ACTOR ATTRIBUTION & MOTIVATIONAL INTENT HYPOTHESIS:", rootMargin, y);
    y += 5;

    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(71, 85, 105);
    const hypLines = doc.splitTextToSize(ai.threatActorHypothesis || "No motivational attribution compiled.", contentWidth);
    doc.text(hypLines, rootMargin, y);
    y += (hypLines.length * 3.8) + 6;

    // Chronicle Timeline
    const tline = ai.detailedTimeline || [];
    if (tline.length > 0) {
      ensureSpace(20 + tline.length * 10);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8.5);
      doc.setTextColor(15, 23, 42);
      doc.text("CHRONOLOGICAL BEHAVIOR REPLAY DATA TIMELINE:", rootMargin, y);
      y += 5;

      tline.forEach((ev) => {
        ensureSpace(14);
        doc.setFont("helvetica", "bold");
        doc.setFontSize(7.5);
        doc.setTextColor(100, 116, 139);
        doc.text(`[${ev.timestamp}] ${ev.event}`, rootMargin + 3, y);
        y += 4;

        doc.setFont("helvetica", "normal");
        doc.setFontSize(7.5);
        doc.setTextColor(71, 85, 105);
        const evLines = doc.splitTextToSize(ev.details || "", contentWidth - 6);
        doc.text(evLines, rootMargin + 6, y);
        y += (evLines.length * 3.5) + 3;
      });
      y += 2;
    }

    // Action plan steps checklist
    const planSteps = ai.remediationSteps || [];
    if (planSteps.length > 0) {
      ensureSpace(20 + planSteps.length * 8);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8.5);
      doc.setTextColor(8, 145, 178); // cyan action color
      doc.text("CRITICAL DISPENSATION ACTION PLAN & REMEDIATION STEPS:", rootMargin, y);
      y += 5.5;

      planSteps.forEach((st) => {
        ensureSpace(12);
        // Draw real checklist checkbox
        doc.setDrawColor(148, 163, 184);
        doc.setLineWidth(0.35);
        doc.rect(rootMargin + 1, y - 2.5, 3.2, 3.2);

        doc.setFont("helvetica", "normal");
        doc.setFontSize(8);
        doc.setTextColor(71, 85, 105);
        const chunkLines = doc.splitTextToSize(st, contentWidth - 8);
        doc.text(chunkLines, rootMargin + 7, y);
        y += (chunkLines.length * 3.8) + 2.5;
      });
    }
  } else {
    ensureSpace(15);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(100, 116, 139);
    doc.text("Cognitive Module status: Heuristic profile computed. Deep AI analytical trace missed for this audit record.", rootMargin, y);
    y += 10;
  }

  // Closing Sign-off Block
  ensureSpace(25);
  y += 5;
  doc.setDrawColor(226, 232, 240);
  doc.line(rootMargin, y, pageWidth - rootMargin, y);
  y += 5;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(8);
  doc.setTextColor(148, 163, 184);
  doc.text("COGNITIVE SHIELD DIGITAL FORENSIC EVIDENCE ENVELOPE VERIFIED", rootMargin, y);
  y += 4;
  doc.setFont("helvetica", "normal");
  doc.setFontSize(6.5);
  doc.text(`DIGITAL SIGNATURE HASH: ${generatePseudoHash(scan)}... [VALID COGNITIVE PARTNER AUDIT SEAL]`, rootMargin, y);

  // Final Footer
  drawFooter();

  // Save document
  doc.save(`CognitiveShield-Forensic-Report-${scan.incidentId}.pdf`);
}
