import React, { useState, useMemo } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Mail, X, Copy, Check, Search, AlertTriangle, ShieldCheck, ShieldAlert, FileCode, Eye, MessageSquare, Clock } from "lucide-react";
import { ScanRecord } from "../types.js";

interface EmailPreviewModalProps {
  isOpen: boolean;
  onClose: () => void;
  record: ScanRecord | null;
}

export function EmailPreviewModal({ isOpen, onClose, record }: EmailPreviewModalProps) {
  const [activeTab, setActiveTab] = useState<"formatted" | "raw" | "envelope">("formatted");
  const [searchQuery, setSearchQuery] = useState("");
  const [copied, setCopied] = useState(false);

  // Auto-generate realistic raw SMTP trace headers if rawEmail/headers are missing
  const rawSMTPHeaders = useMemo(() => {
    if (!record) return "";
    const receivedFromIp = record.headerFindings?.senderIp || "209.85.220.41";
    const statusSpf = record.headerFindings?.spf || "PASS";
    const statusDkim = record.headerFindings?.dkim || "PASS";
    const statusDmarc = record.headerFindings?.dmarc || "PASS";

    return [
      `Delivered-To: soc-vault-inbox@corporation-defense.internal`,
      `Received: from mail-issuer.external.net (${receivedFromIp})`,
      `          by mx.google.com with ESMTPS id q187si53184pfb.122.2026.05.25.07.12.00`,
      `          for <soc-vault-inbox@corporation-defense.internal>;`,
      `          ${new Date(record.createdAt).toUTCString()}`,
      `ARC-Seal: i=1; a=rsa-sha256; t=1716617520; cv=none;`,
      `ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=defense.internal;`,
      `Return-Path: <${record.sender}>`,
      `Received-SPF: ${statusSpf.toLowerCase()} (google.com: domain of ${record.sender} designates ${receivedFromIp} as permitted sender) client-ip=${receivedFromIp};`,
      `Authentication-Results: mx.google.com;`,
      `       spf=${statusSpf.toLowerCase()} (google.com: domain of ${record.sender} designates ${receivedFromIp} as permitted sender) smtp.mailfrom=${record.sender};`,
      `       dkim=${statusDkim.toLowerCase()} header.i=@${record.sender.split("@")[1] || "external.net"};`,
      `       dmarc=${statusDmarc.toLowerCase()} (p=REJECT sp=REJECT dis=NONE) header.from=${record.sender.split("@")[1] || "external.net"}`,
      `From: "${record.sender.split("@")[0]}" <${record.sender}>`,
      `To: "System Security Analyst" <soc-vault-inbox@corporation-defense.internal>`,
      `Subject: ${record.subject}`,
      `Date: ${new Date(record.createdAt).toUTCString()}`,
      `Message-ID: <${record.id || "msg_" + Math.random().toString(36).substr(2, 9)}@mail-defense-soc.internal>`,
      `MIME-Version: 1.0`,
      `Content-Type: text/plain; charset="UTF-8"`,
      `Content-Transfer-Encoding: 7bit`,
      `X-Defended-By: SOC Security Gateway v3.11`,
      `X-Threat-Risk-Index: ${record.threatScore}/100`,
      `X-Threat-Label-Classification: ${record.prediction.toUpperCase()}`,
      `X-Incident-Reference-UUID: ${record.incidentId}`,
      ``,
      `${record.body}`
    ].join("\n");
  }, [record]);

  const handleCopy = () => {
    if (!record) return;
    const textToCopy = activeTab === "raw" ? rawSMTPHeaders : record.body;
    navigator.clipboard.writeText(textToCopy);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  // Safe highlight rendering utilizing simple node splitting
  const highlightedBody = useMemo(() => {
    if (!record?.body) return null;
    const text = record.body;
    if (!searchQuery.trim()) {
      // Highlight classic suspicious keywords organically if no active query
      const phishingKeywords = ["verify", "urgent", "update", "bank", "credit", "netflix", "billing", "unauthorized", "login", "password", "suspended", "action required"];
      let regexStr = phishingKeywords.join("|");
      
      // Also highlight external URLs extracted
      if (record.urlFindings && record.urlFindings.length > 0) {
        const urls = record.urlFindings.map(u => u.url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
        regexStr += "|" + urls.join("|");
      }

      const regex = new RegExp(`\\b(${regexStr})\\b`, "gi");
      const parts = text.split(regex);
      if (parts.length === 1) return <span>{text}</span>;

      return (
        <span>
          {parts.map((part, idx) => {
            const isMatch = regex.test(part) || (record.urlFindings?.some(u => u.url.toLowerCase() === part.toLowerCase()) ?? false);
            const isUrl = record.urlFindings?.some(u => u.url.toLowerCase() === part.toLowerCase()) ?? false;

            if (isMatch) {
              return (
                <span
                  key={idx}
                  className={`px-1 py-0.5 rounded font-semibold ${
                    isUrl
                      ? "bg-rose-500/10 text-rose-400 border border-rose-500/20 underline decoration-rose-500/50 cursor-pointer"
                      : "bg-amber-500/15 text-amber-300 border border-amber-500/25"
                  }`}
                  title={isUrl ? "Suspicious extracted payload URL node" : "Security critical keyword matches"}
                >
                  {part}
                </span>
              );
            }
            return <span key={idx}>{part}</span>;
          })}
        </span>
      );
    }

    // Highlighting custom active query terms
    const escapedQuery = searchQuery.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const regex = new RegExp(`(${escapedQuery})`, "gi");
    const parts = text.split(regex);

    return (
      <span>
        {parts.map((part, idx) => (
          regex.test(part) ? (
            <mark key={idx} className="bg-cyan-500/30 text-white rounded px-0.5 border border-cyan-500/20">
              {part}
            </mark>
          ) : (
            <span key={idx}>{part}</span>
          )
        ))}
      </span>
    );
  }, [record, searchQuery]);

  if (!isOpen || !record) return null;

  const isPhishing = record.prediction === "Phishing";

  return (
    <AnimatePresence>
      <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
        {/* Dark blurred background overlay */}
        <motion.div
          id="email-preview-overlay"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          onClick={onClose}
          className="absolute inset-0 bg-slate-950/80 backdrop-blur-sm"
        />

        {/* Modal Window Panel */}
        <motion.div
          id="email-preview-modal-panel"
          initial={{ opacity: 0, scale: 0.95, y: 15 }}
          animate={{ opacity: 1, scale: 1, y: 0 }}
          exit={{ opacity: 0, scale: 0.95, y: 15 }}
          transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
          className="relative bg-[#0c121d] border border-slate-800 rounded-2xl shadow-[0_10px_50px_rgba(0,0,0,0.8)] w-full max-w-4xl h-[85vh] flex flex-col overflow-hidden z-10"
        >
          {/* Header Action Row */}
          <div className="p-4 sm:p-5 border-b border-slate-800/80 bg-slate-950/40 flex items-center justify-between gap-4">
            <div className="flex items-center gap-3">
              <div className={`p-2.5 rounded-xl border ${
                isPhishing
                  ? "bg-rose-500/10 border-rose-500/30 text-rose-400 animate-pulse"
                  : "bg-cyan-500/10 border-cyan-500/30 text-cyan-400"
              }`}>
                <Mail className="w-5 h-5" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono text-slate-500 uppercase tracking-widest font-semibold">Incident Email Source Review</span>
                  <span className={`px-2 py-0.5 rounded text-[9px] font-mono border ${
                    isPhishing
                      ? "bg-rose-500/10 text-rose-400 border-rose-500/20"
                      : "bg-cyan-500/10 text-cyan-400 border-cyan-500/20"
                  }`}>
                    {record.incidentId}
                  </span>
                </div>
                <h3 className="text-sm sm:text-base font-bold text-white max-w-xl truncate mt-0.5">
                  {record.subject}
                </h3>
              </div>
            </div>

            <button
              id="close-email-preview-btn"
              type="button"
              onClick={onClose}
              className="text-slate-400 hover:text-white p-1.5 hover:bg-slate-900 border border-transparent hover:border-slate-800 rounded-lg cursor-pointer transition-all"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Quick Stats Metadata Bar */}
          <div className="bg-slate-950/60 px-5 py-3 border-b border-slate-850/70 grid grid-cols-2 md:grid-cols-4 gap-4 text-xs font-mono text-slate-400">
            <div>
              <span className="text-[10px] text-slate-550 uppercase tracking-wider block">Sender Identifier</span>
              <span className="text-slate-200 mt-0.5 block truncate" title={record.sender}>{record.sender}</span>
            </div>
            <div>
              <span className="text-[10px] text-slate-550 uppercase tracking-wider block">Gateway Assessment</span>
              <span className={`font-bold mt-0.5 block ${isPhishing ? "text-rose-400" : "text-cyan-400"}`}>
                ● {record.prediction.toUpperCase()} ({record.threatScore}%)
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-550 uppercase tracking-wider block">Received Date</span>
              <span className="text-slate-200 mt-0.5 block truncate">
                {new Date(record.createdAt).toLocaleString(undefined, {month: "short", day: "numeric", hour: "2-digit", minute: "2-digit"})}
              </span>
            </div>
            <div>
              <span className="text-[10px] text-slate-550 uppercase tracking-wider block">Route IP Context</span>
              <span className="text-slate-200 mt-0.5 block">
                {record.headerFindings?.senderIp || "127.0.0.1"}
              </span>
            </div>
          </div>

          {/* Tab Selection Filter Row */}
          <div className="bg-[#0b111a] px-5 pt-3 border-b border-slate-850/80 flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3">
            <div className="flex gap-2 text-xs font-mono">
              <button
                type="button"
                onClick={() => setActiveTab("formatted")}
                className={`pb-2.5 px-3 border-b-2 font-bold cursor-pointer transition-all flex items-center gap-1.5 ${
                  activeTab === "formatted"
                    ? "border-cyan-500 text-cyan-400"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <Eye className="w-3.5 h-3.5" /> Formatted View
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("raw")}
                className={`pb-2.5 px-3 border-b-2 font-bold cursor-pointer transition-all flex items-center gap-1.5 ${
                  activeTab === "raw"
                    ? "border-cyan-500 text-cyan-400"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <FileCode className="w-3.5 h-3.5" /> Raw MIME Stream
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("envelope")}
                className={`pb-2.5 px-3 border-b-2 font-bold cursor-pointer transition-all flex items-center gap-1.5 ${
                  activeTab === "envelope"
                    ? "border-cyan-500 text-cyan-400"
                    : "border-transparent text-slate-400 hover:text-slate-200"
                }`}
              >
                <MessageSquare className="w-3.5 h-3.5" /> SMTP Diagnostics
              </button>
            </div>

            {/* In-Modal Telemetry Search Bar & Copy Buttons */}
            <div className="flex items-center gap-2 pb-2.5 sm:pb-0">
              {activeTab === "formatted" && (
                <div className="relative">
                  <span className="absolute inset-y-0 left-3 flex items-center pointer-events-none">
                    <Search className="w-3 h-3 text-slate-500" />
                  </span>
                  <input
                    type="text"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search terms in mail body..."
                    className="bg-slate-950 border border-slate-800 text-[11px] font-mono text-slate-200 rounded-lg pl-8 pr-3 py-1.5 w-52 focus:outline-none focus:border-cyan-500 transition-all text-ellipsis"
                  />
                  {searchQuery && (
                    <button
                      type="button"
                      onClick={() => setSearchQuery("")}
                      className="absolute inset-y-0 right-2 px-1 text-[10px] text-slate-500 hover:text-slate-350 font-mono"
                    >
                      Clear
                    </button>
                  )}
                </div>
              )}

              <button
                type="button"
                onClick={handleCopy}
                className="bg-slate-950 border border-slate-800 hover:border-slate-700 hover:bg-slate-900 text-slate-300 py-1.5 px-2.5 rounded-lg text-[11px] font-mono transition-all flex items-center gap-1.5 cursor-pointer focus:outline-none shrink-0"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-450" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5 text-slate-450" />
                    <span>Copy Text</span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Central Modal Content Scrollable Area */}
          <div className="flex-1 overflow-y-auto p-5 sm:p-6 bg-[#090e16]/80 text-sm leading-relaxed">
            {activeTab === "formatted" ? (
              <div className="space-y-4">
                {/* Active Suspicious Match Alert Indicator Box */}
                {isPhishing && (
                  <div className="bg-rose-500/5 border border-rose-500/20 p-4 rounded-xl flex items-start gap-3">
                    <AlertTriangle className="w-4.5 h-4.5 text-rose-500 shrink-0 mt-0.5" />
                    <div className="text-xs">
                      <h4 className="font-bold text-rose-400 font-mono">[THREAT_DETECTION]: High Risk Indicators Identified</h4>
                      <p className="text-slate-450 mt-1 leading-relaxed">
                        This document stream exhibits signature vectors for brand spoofing and/or urgent calls-to-action. Clickable nodes or sensitive words have been flagged with a custom highlighting structure below.
                      </p>
                    </div>
                  </div>
                )}

                {/* Simulated Mail Client Window Wrapper */}
                <div className="bg-slate-950/40 border border-slate-850 rounded-xl p-5 font-sans relative">
                  {/* Subtle watermarked grid background */}
                  <div className="absolute inset-0 bg-grid-pattern opacity-5 pointer-events-none rounded-xl" />

                  {/* Mail Message Header Info Block */}
                  <div className="border-b border-slate-900 pb-4 mb-4 space-y-2 text-xs text-slate-400">
                    <div>
                      <span className="font-mono text-slate-550 mr-2 uppercase">From:</span>
                      <strong className="text-slate-200">{record.sender}</strong>
                    </div>
                    <div>
                      <span className="font-mono text-slate-550 mr-2 uppercase">To:</span>
                      <span className="text-slate-300">system-analyst@defense.internal</span>
                    </div>
                    <div>
                      <span className="font-mono text-slate-550 mr-2 uppercase">Date:</span>
                      <span className="text-slate-350">{new Date(record.createdAt).toUTCString()}</span>
                    </div>
                    <div>
                      <span className="font-mono text-slate-550 mr-2 uppercase">Subject:</span>
                      <span className="text-slate-100 font-semibold">{record.subject}</span>
                    </div>
                  </div>

                  {/* Highlighted Body Paragraph */}
                  <div className="text-slate-300 font-sans tracking-wide leading-relaxed text-sm whitespace-pre-wrap select-text selection:bg-cyan-500/30">
                    {highlightedBody}
                  </div>
                </div>

                {/* Suspicious URL Registry */}
                {record.urlFindings && record.urlFindings.length > 0 && (
                  <div className="bg-slate-950/30 border border-slate-850 rounded-xl p-4 space-y-2.5">
                    <h4 className="text-[11px] font-mono text-slate-400 uppercase tracking-wider flex items-center gap-1.5 font-bold">
                      <AlertTriangle className="w-3.5 h-3.5 text-amber-500" /> Extracted URL Payload Elements
                    </h4>
                    <div className="divide-y divide-slate-900 text-xs">
                      {record.urlFindings.map((url, i) => {
                        const isMalicious = url.isBlacklisted || url.riskScore > 70;
                        const label = url.isBlacklisted ? "BLACKLISTED" : url.riskScore > 40 ? "SUSPICIOUS" : "SAFE";
                        return (
                          <div key={i} className="py-2 flex flex-col sm:flex-row sm:items-center sm:justify-between gap-1">
                            <code className="text-rose-400 font-mono break-all">{url.url}</code>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-mono w-fit ${
                              isMalicious
                                ? "bg-rose-500/10 text-rose-400 border border-rose-500/20"
                                : url.riskScore > 40
                                ? "bg-amber-500/10 text-amber-400 border border-amber-500/20"
                                : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                            }`}>
                              {label} ({url.riskScore}%)
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            ) : activeTab === "raw" ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between text-[11px] font-mono text-slate-530 bg-[#070c13] px-3.5 py-2 rounded-t-xl border-x border-t border-slate-850">
                  <span className="flex items-center gap-1.5">
                    <Clock className="w-3.5 h-3.5 text-cyan-500" /> FULL SMTP MAIL HOP ENVELOPE STREAM
                  </span>
                  <span>ENCRYPTED VIA TLS 1.3</span>
                </div>
                <div className="bg-slate-950 border border-slate-850 rounded-b-xl p-4.5 font-mono text-[11px] text-slate-350 leading-relaxed overflow-x-auto select-all selection:bg-cyan-500/30">
                  <pre className="whitespace-pre-wrap break-all pr-2">{rawSMTPHeaders}</pre>
                </div>
              </div>
            ) : (
              <div className="space-y-6">
                {/* SMTP Auth checks panel */}
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {/* SPF Check */}
                  <div className="bg-slate-950/40 border border-slate-850 p-4 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-slate-400">SPF AUTH MATCH</span>
                      {record.headerFindings?.spf === "PASS" ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-rose-500" />
                      )}
                    </div>
                    <div className="font-mono text-lg font-black text-white">
                      {record.headerFindings?.spf || "PASS"}
                    </div>
                    <p className="text-[10px] text-slate-500 leading-relaxed font-sans">
                      Sender Policy Framework confirms that the outgoing SMTP server is authorized to dispatch mail from this domain.
                    </p>
                  </div>

                  {/* DKIM Check */}
                  <div className="bg-slate-950/40 border border-slate-850 p-4 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-slate-400">DKIM CRYPTO SIGN</span>
                      {record.headerFindings?.dkim === "PASS" ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-rose-500" />
                      )}
                    </div>
                    <div className="font-mono text-lg font-black text-white">
                      {record.headerFindings?.dkim || "PASS"}
                    </div>
                    <p className="text-[10px] text-slate-500 leading-relaxed font-sans">
                      DomainKeys Identified Mail verifies cryptographic digital handshakes matches original domain configurations.
                    </p>
                  </div>

                  {/* DMARC Check */}
                  <div className="bg-slate-950/40 border border-slate-850 p-4 rounded-xl space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono text-slate-400">DMARC POLICY ALIGN</span>
                      {record.headerFindings?.dmarc === "PASS" ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-rose-500" />
                      )}
                    </div>
                    <div className="font-mono text-lg font-black text-white">
                      {record.headerFindings?.dmarc || "PASS"}
                    </div>
                    <p className="text-[10px] text-slate-500 leading-relaxed font-sans">
                      Domain-based Message Authentication Reporting instructs policies on discrepancies or spoofing attempts.
                    </p>
                  </div>
                </div>

                {/* Routing Anomalies Checklist */}
                <div className="bg-slate-950/40 border border-slate-850 rounded-xl p-5 space-y-3">
                  <h4 className="text-xs font-mono text-slate-300 uppercase tracking-wider font-semibold">Security Analysed Envelope Anomalies</h4>
                  <ul className="divide-y divide-slate-900">
                    {record.headerFindings?.anomalies && record.headerFindings.anomalies.length > 0 ? (
                      record.headerFindings.anomalies.map((anom, idx) => (
                        <li key={idx} className="py-2.5 text-xs font-mono flex items-start gap-2.5 text-rose-400">
                          <AlertTriangle className="w-3.5 h-3.5 text-rose-500 shrink-0 mt-0.5" />
                          <span>{anom}</span>
                        </li>
                      ))
                    ) : (
                      <li className="py-2.5 text-xs text-slate-500 font-mono flex items-center gap-2">
                        <ShieldCheck className="w-4 h-4 text-cyan-400" /> No routing anomalies triggered on mail headers.
                      </li>
                    )}
                  </ul>
                </div>
              </div>
            )}
          </div>

          {/* Footer Navigation Information Bar */}
          <div className="p-4 bg-slate-950/80 border-t border-slate-850 flex flex-col sm:flex-row items-center justify-between gap-3 text-[10px] font-mono text-slate-500">
            <div className="flex items-center gap-1">
              <span>SECURITY INTEL ANALYSERS VERDICT:</span>
              <span className={`font-bold uppercase ${isPhishing ? "text-rose-500" : "text-cyan-400"}`}>
                {record.prediction} (Confidence: {record.confidenceScore}%)
              </span>
            </div>
            <span>ANALYZED BY NODE: {record.analyzedBy || "SOCOG_VM_CORE"}</span>
          </div>
        </motion.div>
      </div>
    </AnimatePresence>
  );
}
