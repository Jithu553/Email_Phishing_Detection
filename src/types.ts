/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export enum ThreatLevel {
  LOW = "Low",
  MEDIUM = "Medium",
  HIGH = "High",
  CRITICAL = "Critical"
}

export enum UserRole {
  ADMIN = "Admin",
  ANALYST = "Security Analyst"
}

export interface User {
  id: string;
  username: string;
  email: string;
  role: UserRole;
  createdAt: string;
}

export interface HeaderFindings {
  senderIp: string;
  spf: "PASS" | "FAIL" | "NONE" | "SOFTFAIL";
  dkim: "PASS" | "FAIL" | "NONE";
  dmarc: "PASS" | "FAIL" | "NONE";
  receivedPath: string[];
  anomalies: string[];
  timestamp: string;
  returnPath: string;
  domainAgeDays?: number;
}

export interface UrlFinding {
  url: string;
  domain: string;
  isHttps: boolean;
  isBlacklisted: boolean;
  isShortened: boolean;
  suspiciousKeywordsMatched: string[];
  riskScore: number; // 0-100
}

export interface AttachmentFinding {
  fileName: string;
  fileSize: number;
  extension: string;
  md5Hash: string;
  sha256Hash: string;
  hasMacro: boolean;
  isExecutable: boolean;
  isSuspicious: boolean;
  dangerLevel: "SAFE" | "SUSPICIOUS" | "MALICIOUS";
}

export interface AiForensicResult {
  socialEngineeringTactics: string[];
  summary: string;
  phishingIndicators: string[];
  detailedTimeline: { event: string; timestamp: string; details: string }[];
  threatActorHypothesis: string;
  remediationSteps: string[];
}

export interface ScanRecord {
  id: string;
  incidentId: string;
  subject: string;
  sender: string;
  body: string;
  rawEmail?: string;
  headers?: string;
  prediction: "Legitimate" | "Phishing";
  confidenceScore: number; // 0-100
  threatScore: number; // 0-100
  threatLevel: ThreatLevel;
  headerFindings?: HeaderFindings;
  urlFindings?: UrlFinding[];
  attachmentFindings?: AttachmentFinding[];
  aiForensicAnalysis?: AiForensicResult;
  analyzedBy: string;
  createdAt: string;
}

export interface AuditLog {
  id: string;
  username: string;
  action: string;
  details: string;
  ip: string;
  createdAt: string;
}

export interface DashboardStats {
  totalScanned: number;
  totalPhishing: number;
  totalLegitimate: number;
  threatDistribution: {
    low: number;
    medium: number;
    high: number;
    critical: number;
  };
  monthlyTrends: {
    month: string;
    scanned: number;
    phishing: number;
  }[];
  topAttackSources: {
    domain: string;
    count: number;
  }[];
  recentInvestigations: ScanRecord[];
  threatTrends30Days: {
    date: string;
    low: number;
    medium: number;
    high: number;
    critical: number;
  }[];
}

export interface LoginAttempt {
  id: string;
  username: string;
  ip: string;
  status: "SUCCESS" | "FAILED" | "BLOCKED";
  createdAt: string;
}

export interface BannedIp {
  ip: string;
  reason: string;
  createdAt: string;
}
