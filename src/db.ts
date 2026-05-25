/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from "fs";
import path from "path";
import crypto from "crypto";
import { User, UserRole, ScanRecord, AuditLog, ThreatLevel } from "./types.js";

const DB_FILE = path.join(process.cwd(), "phish_db.json");

// Helper to hash password securely
export function hashPassword(password: string): string {
  return crypto.createHash("sha256").update(password).digest("hex");
}

export interface DatabaseSchema {
  users: any[];
  scans: ScanRecord[];
  auditLogs: AuditLog[];
}

// Pre-populate some realistic investigations for the dashboard
const INITIAL_SCANS: ScanRecord[] = [
  {
    id: "scan_101",
    incidentId: "INC-2026-8801",
    subject: "Alert: Login Suspended - Secure Auth Required",
    sender: "no-reply@security-verification-portal.com.co",
    body: "Attention: We observed a suspicious login from a remote location. To ensure the safety of your funds, we have temporarily suspended your account. Click the button below to reactivate now: http://login-reactivation-page.net/account-verify",
    prediction: "Phishing",
    confidenceScore: 97,
    threatScore: 92,
    threatLevel: ThreatLevel.CRITICAL,
    analyzedBy: "analyst",
    createdAt: new Date(Date.now() - 3600000 * 24 * 3).toISOString(), // 3 days ago
    headerFindings: {
      senderIp: "185.220.101.44",
      spf: "FAIL",
      dkim: "FAIL",
      dmarc: "FAIL",
      receivedPath: ["185.220.101.44 (Tor Exit Node)", "192.168.1.1 (Internal)"],
      anomalies: [
        "Sender IP listed on multiple RBL blacklists (Tor Exit Node)",
        "DMARC authentication failed completely",
        "Sender domain '.com.co' mismatches claiming security identity"
      ],
      timestamp: new Date(Date.now() - 3600000 * 24 * 3).toISOString(),
      returnPath: "bounce@secured-verification.com.co",
      domainAgeDays: 4
    },
    urlFindings: [
      {
        url: "http://login-reactivation-page.net/account-verify",
        domain: "login-reactivation-page.net",
        isHttps: false,
        isBlacklisted: true,
        isShortened: false,
        suspiciousKeywordsMatched: ["login", "verify", "reactivation"],
        riskScore: 95
      }
    ],
    attachmentFindings: [],
    aiForensicAnalysis: {
      socialEngineeringTactics: ["Fear / Urgency", "Authority Impersonation"],
      summary: "High confidence phishing campaign targeting financial credentials using cloned authorization pathways. The sender IP matches known threat actor relays.",
      phishingIndicators: [
        "Unauthenticated email headers (SPF/DKIM failed)",
        "Plain HTTP unencrypted credential submission form",
        "Sender domain registered less than 7 days ago"
      ],
      detailedTimeline: [
        { event: "Email Received", timestamp: new Date(Date.now() - 3600000 * 24 * 3).toISOString(), details: "Inbound Tor Exit Node relay routed via compromised port" },
        { event: "Heuristic Parse", timestamp: new Date(Date.now() - 3600000 * 24 * 3 + 12000).toISOString(), details: "Extracted non-HTTPS suspicious domain" },
        { event: "ML Evaluation", timestamp: new Date(Date.now() - 3600000 * 24 * 3 + 15000).toISOString(), details: "Classified as Phishing (confidence: 97%)" }
      ],
      threatActorHypothesis: "Suspected deployment by advanced persistent threat group (APT-29 mimic) seeking user base authentication bypasses.",
      remediationSteps: [
        "Block IP range 185.220.101.0/24",
        "Sinkhole domain login-reactivation-page.net in local DNS blacklist",
        "Send alert notification to security analyst queue"
      ]
    }
  },
  {
    id: "scan_102",
    incidentId: "INC-2026-8802",
    subject: "Overdue Statement Invoice #556272",
    sender: "accounts@billing-department-portal.link",
    body: "Hi Team, Please find attached our invoice #556272 which is heavily outstanding. Kindly click on invoice-view.com/payment.html to process using secure merchant portal. Attached is the transaction timeline proof: invoice_audit.js",
    prediction: "Phishing",
    confidenceScore: 89,
    threatScore: 78,
    threatLevel: ThreatLevel.HIGH,
    analyzedBy: "admin",
    createdAt: new Date(Date.now() - 3600000 * 12).toISOString(), // 12 hours ago
    headerFindings: {
      senderIp: "203.0.113.88",
      spf: "PASS",
      dkim: "NONE",
      dmarc: "FAIL",
      receivedPath: ["203.0.113.88", "10.0.0.9"],
      anomalies: [
        "DKIM signature missing while claiming financial transaction corporate origin",
        "Return path bounces to unmonitored mailbox structure"
      ],
      timestamp: new Date(Date.now() - 3600000 * 12).toISOString(),
      returnPath: "bounce-billing@billing-department-portal.link"
    },
    urlFindings: [
      {
        url: "http://invoice-view.com/payment.html",
        domain: "invoice-view.com",
        isHttps: false,
        isBlacklisted: false,
        isShortened: false,
        suspiciousKeywordsMatched: ["invoice", "payment"],
        riskScore: 70
      }
    ],
    attachmentFindings: [
      {
        fileName: "invoice_audit.js",
        fileSize: 4200,
        extension: "js",
        md5Hash: "9e107d9d372bb6826bd81d3542a419d6",
        sha256Hash: "f15e8e81df6f505db172fccf42e47c1eb48bd2e8ab710189d97bf97d62058378",
        hasMacro: false,
        isExecutable: true,
        isSuspicious: true,
        dangerLevel: "MALICIOUS"
      }
    ],
    aiForensicAnalysis: {
      socialEngineeringTactics: ["Financial Inducement", "Urgency"],
      summary: "Malicious javascript file attachment masking as an outstanding invoice ledger. When clicked, it initiates background payload distribution.",
      phishingIndicators: [
        "Active executable content script attached directly",
        "Sender claims Billing title without enterprise authentication keys"
      ],
      detailedTimeline: [
        { event: "Email Received", timestamp: new Date(Date.now() - 3600000 * 12).toISOString(), details: "Inbound ingress node relay" },
        { event: "Sandbox Extract", timestamp: new Date(Date.now() - 3600000 * 12 + 4000).toISOString(), details: "Extracted JavaScript attachment and computed SHA256 hashes" }
      ],
      threatActorHypothesis: "Targeted finance department phishing campaign seeking initial payload execution on workplace end-points.",
      remediationSteps: [
        "Block inbound attachments with active extensions (.js, .exe, .scr)",
        "Quarantine attachment on network gateways"
      ]
    }
  },
  {
    id: "scan_103",
    incidentId: "INC-2026-8803",
    subject: "Project Deadline Deliverables - Shift Report",
    sender: "team-lead@company-corp.com",
    body: "Hi everyone, here are the updated sprint metrics and deliverables. Let's make sure everything is aligned for our retro tomorrow at 10 AM.",
    prediction: "Legitimate",
    confidenceScore: 98,
    threatScore: 5,
    threatLevel: ThreatLevel.LOW,
    analyzedBy: "analyst",
    createdAt: new Date(Date.now() - 3600000 * 48).toISOString(), // 2 days ago
    headerFindings: {
      senderIp: "12.33.44.55",
      spf: "PASS",
      dkim: "PASS",
      dmarc: "PASS",
      receivedPath: ["12.33.44.55 (Enterprise gateway)", "10.10.10.1 (MX)"],
      anomalies: [],
      timestamp: new Date(Date.now() - 3600000 * 48).toISOString(),
      returnPath: "team-lead@company-corp.com"
    },
    urlFindings: [],
    attachmentFindings: [],
    aiForensicAnalysis: {
      socialEngineeringTactics: [],
      summary: "Legitimate internal communication. High SPF, DKIM, and DMARC alignment matched.",
      phishingIndicators: [],
      detailedTimeline: [],
      threatActorHypothesis: "No anomalies detected.",
      remediationSteps: ["White-listed safe communications pipeline"]
    }
  }
];

class Database {
  private data: DatabaseSchema;

  constructor() {
    this.data = {
      users: [],
      scans: [],
      auditLogs: []
    };
    this.load();
  }

  private load() {
    try {
      if (fs.existsSync(DB_FILE)) {
        const fileContent = fs.readFileSync(DB_FILE, "utf-8");
        this.data = JSON.parse(fileContent);
      } else {
        // Initialize default credentials and scans
        const adminPassHash = hashPassword("admin123");
        const analystPassHash = hashPassword("analyst123");

        this.data = {
          users: [
            {
              id: "u_1",
              username: "admin",
              email: "admin@phishforensic.ai",
              passwordHash: adminPassHash,
              role: UserRole.ADMIN,
              createdAt: new Date().toISOString()
            },
            {
              id: "u_2",
              username: "analyst",
              email: "analyst@phishforensic.ai",
              passwordHash: analystPassHash,
              role: UserRole.ANALYST,
              createdAt: new Date().toISOString()
            }
          ],
          scans: INITIAL_SCANS,
          auditLogs: [
            {
              id: "log_1",
              username: "system",
              action: "Database Bootstrapped",
              details: "Security databases initialized with default SOC profiles and training sets",
              ip: "127.0.0.1",
              createdAt: new Date().toISOString()
            }
          ]
        };
        this.save();
      }
    } catch (err) {
      console.error("Failed to load local database, falling back to memory:", err);
    }
  }

  private save() {
    try {
      fs.writeFileSync(DB_FILE, JSON.stringify(this.data, null, 2), "utf-8");
    } catch (err) {
      console.error("Failed to save local database:", err);
    }
  }

  // User methods
  public getUsers() {
    return this.data.users;
  }

  public getUserByUsername(username: string) {
    return this.data.users.find(u => u.username.toLowerCase() === username.toLowerCase());
  }

  public getUserByEmail(email: string) {
    return this.data.users.find(u => u.email.toLowerCase() === email.toLowerCase());
  }

  public registerUser(username: string, email: string, passwordHash: string, role: UserRole) {
    const newUser = {
      id: "u_" + Math.random().toString(36).substr(2, 9),
      username,
      email,
      passwordHash,
      role,
      createdAt: new Date().toISOString()
    };
    this.data.users.push(newUser);
    this.save();
    return newUser;
  }

  public deleteUser(username: string) {
    this.data.users = this.data.users.filter(u => u.username.toLowerCase() !== username.toLowerCase());
    this.save();
  }

  // Scan Record methods
  public getScans() {
    return this.data.scans;
  }

  public getScanById(id: string) {
    return this.data.scans.find(s => s.id === id);
  }

  public addScan(scan: Omit<ScanRecord, "id">) {
    const newScan: ScanRecord = {
      ...scan,
      id: "scan_" + Math.random().toString(36).substr(2, 9)
    };
    this.data.scans.unshift(newScan); // Newest first
    this.save();
    return newScan;
  }

  public deleteScan(id: string) {
    this.data.scans = this.data.scans.filter(s => s.id !== id);
    this.save();
  }

  // Audit Logs methods
  public getLogs() {
    return this.data.auditLogs;
  }

  public addLog(username: string, action: string, details: string, ip: string) {
    const log: AuditLog = {
      id: "log_" + Math.random().toString(36).substr(2, 9),
      username,
      action,
      details,
      ip,
      createdAt: new Date().toISOString()
    };
    this.data.auditLogs.unshift(log); // newest logs first
    this.save();
    return log;
  }

  public deleteLogs() {
    this.data.auditLogs = [];
    this.save();
  }
}

export const db = new Database();
