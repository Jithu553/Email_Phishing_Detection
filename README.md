# AI-Driven Real-Time Email Phishing Detection & Investigation Platform

An intelligent, cloud-ready cyber security digital forensics and machine learning platform designed to audit electronic mail structures, predict phishing exploits using Natural Language Processing (NLP), and carry out cognitive sandbox threat investigations.

Perfect for Final Year Projects, cyber security demonstrations, portfolio compilations, and presentation.

---

## 🚀 Key Highlights & Capabilities
- **Role-Based Authentication**: Secure JWT terminal system separating clearance logs for Administrator (`Admin`) and Threat Analyst (`Security Analyst`) roles.
- **TF-IDF Classifier Engine**: Supervised mathematical NLP classifier working on cached vocabulary and gradient-descent parameters trained directly on-node. Provides interactive model retraining and confusion matrix results.
- **Heuristic MIME Header Dissector**: Regex parser verifying transport hops logs, extracting sender IP coordinates, and validating SPF, DKIM, and DMARC credentials.
- **Hyperlinks & Payloads Auditor**: Lexical checks matching suspicious keywords patterns, flag shortened redirection triggers, and verifying SSL HTTPS requirements.
- **Dynamic Risk Severity Scorer**: Aggregates all indicators scores (ML confidence, header breaches, URL risks and attachment signatures) to produce weighted priorities level (Low, Medium, High, Critical).
- **Gemini AI Deep Forensics**: Connects server-side to the Gemini 3.5-flash specialist LLM to formulate social engineering threat hypotheses, chronological timeline reviews, and actionable corporate remediation matrices (when API Key is available).
- **Offline Attachment Hashes signatures**: Calculates precise MD5 and SHA-256 evidence logs checksums, checking file extensions and identifying active macro scripts.

---

## 📂 Project Folder Structure

```text
├── server.ts                  # express full-stack server & forensic APIs
├── phish_db.json              # persistent JSON-file database mock collection
├── package.json               # node dependencies and custom ESBuild scripts
├── vite.config.ts             # vite asset compiler and middleware config
├── metadata.json              # aistudio workspace permission configs
├── tsconfig.json              # typings structural requirements
├── README.md                  # full documentation deployment guides
└── src
    ├── App.tsx                # main root router and header dashboards frame
    ├── main.tsx               # system entry mount point
    ├── index.css              # core stylesheet compiling tailwind classes
    ├── types.ts               # shared typescript interfaces, enums and models
    ├── ml_classifier.ts       # TF-IDF machine learning optimizer pipeline
    ├── db.ts                  # database mock collections CRUD helper
    └── components
        ├── LandingPage.tsx    # glowing neon cyber homepage banner
        ├── Auth.tsx           # validation registry onboarding screen
        ├── Dashboard.tsx      # SOC interactive metrics and Recharts graphs
        ├── Analyzer.tsx       # mail threat audit inputs and dossier reporter
        ├── MLWorkbench.tsx    # hyperparameter compiler and convergence logs
        └── AdminPanel.tsx     # user credentials lists and logs purge command
```

---

## 🗄️ Database Schema Representation

The platform uses a file-based JSON database `phish_db.json` which functions exactly like a MongoDB database, containing three unified collections:

### 1. `users` Collection
Tracks registered credentials and clearance levels:
```json
{
  "id": "u_98dksia",
  "username": "analyst_beta",
  "email": "beta@cyber-agency.gov",
  "passwordHash": "a665a45920422f9d417e4867efdc4fb8a0...", // Secure SHA-256 Hash
  "role": "Security Analyst", // Or "Admin"
  "createdAt": "2026-05-25T14:00:00.000Z"
}
```

### 2. `scans` (Investigations) Collection
Stores fully processed forensics dossiers:
```json
{
  "id": "scan_h8sjd1s",
  "incidentId": "INC-2026-8801",
  "subject": "Alert: Secure Auth Required immediately",
  "sender": "no-reply@secure-verify-paypal.cf",
  "prediction": "Phishing",
  "confidenceScore": 97,
  "threatScore": 92,
  "threatLevel": "Critical",
  "headerFindings": {
    "senderIp": "185.220.101.44",
    "spf": "FAIL",
    "dkim": "FAIL",
    "dmarc": "FAIL",
    "receivedPath": ["185.220.101.44"],
    "anomalies": ["Tor Exit Node IP match", "DMARC authentication failed"]
  },
  "urlFindings": [
    {
      "url": "http://paypal-verification-portal.net/login",
      "domain": "paypal-verification-portal.net",
      "isHttps": false,
      "riskScore": 95
    }
  ],
  "attachmentFindings": [],
  "aiForensicAnalysis": {
    "socialEngineeringTactics": ["Fear / Urgency", "Authority Impersonation"],
    "summary": "High confidence phishing campaign targeting financial credentials...",
    "threatActorHypothesis": "APT-29 mimic seeking credential bypassing...",
    "remediationSteps": ["Block Tor IP range 185.220.101.0/24", "Sinkhole domain"]
  },
  "analyzedBy": "analyst_beta",
  "createdAt": "2026-05-25T14:08:00.000Z"
}
```

### 3. `auditLogs` Collection
Maintains strict chronological trace logs of all activity on the nodes:
```json
{
  "id": "log_k8jsia",
  "username": "admin",
  "action": "ML Model Restructured",
  "details": "Classifier model retrained on 12 samples over 150 epochs. New F1 Score: 94%",
  "ip": "127.0.0.1",
  "createdAt": "2026-05-25T14:08:15.000Z"
}
```

---

## ⚡ API Endpoint Schema

All REST API nodes expect/respond in JSON, protected by Auth interception.

| Endpoint | Method | Authentication | Objective |
| :--- | :--- | :--- | :--- |
| `/api/register` | `POST` | Public | Account creation (credentials validation hashing) |
| `/api/login` | `POST` | Public | Session generation (returns authorization JWT token) |
| `/api/upload-email` | `POST` | `JWT Bearer` | Ingests threat text packet. Runs ML model, digests headers and outputs stored incident record |
| `/api/analyze-header` | `POST` | `JWT Bearer` | Analyzes SMTP headers anomalies |
| `/api/analyze-url` | `POST` | `JWT Bearer` | Returns risk evaluation of links |
| `/api/ml/weights` | `GET` | `JWT Bearer` | Returns current vocabulary weights mapping coefficients |
| `/api/ml/retrain` | `POST` | `JWT Bearer` | Compiles training iterations, updating local models weights |
| `/api/dashboard-stats`| `GET` | `JWT Bearer` | Aggregates KPIs, severities distribution and trends |
| `/api/admin/users` | `GET` | `JWT Bearer / Admin` | Returns list of registered analyst accounts |
| `/api/admin/logs` | `GET/DELETE` | `JWT Bearer / Admin` | Reviews or clears the system audit trail logs |

---

## 📈 ML Classification Explained: TF-IDF + Logistic Regression
The platform implements a highly efficient native classifier pipeline in `src/ml_classifier.ts`:
1. **Tokenization**: Slices text strings into matching alphanumeric tokens, filtering fillers.
2. **Frequency Mapping**: Computes **Term Frequency (TF)** normalized to document word count.
3. **Inverse Document Frequency (IDF)**: Calculates global word scarcity coefficients:
   $$IDF(t) = \log\left(\frac{N + 1}{df(t) + 1}\right) + 1$$
4. **Logistic Regression Gradient Descent**: Applies back-propagation loss minimization to optimize coefficients:
   $$p = \frac{1}{1 + e^{-(\beta_0 + \sum w_i x_i)}}$$
   Where $w_i$ represents the TF-IDF feature and $x_i$ the coefficient. In the ML laboratory tab, clicking Retrain recalculates these coefficients live, allowing you to plot the declining cross-entropy loss curve.

---

## 📋 Installation & Fast Local Deployment

To run the full-stack platform locally on your corporate endpoint or virtual machines:

### Prerequisites
Make sure you have **Node.js** (v18+) and npm installed on your terminal.

### 1. Extract & Install Dependencies
Navigate inside the project root and run dependencies downloader:
```bash
npm install
```

### 2. Environment Configurations
Configure a `.env` file in the root:
```env
PORT=3000
JWT_SECRET="academic-secret-key-token-2026"

# Optional: Add key to trigger advanced generative Gemini DFIR reports
GEMINI_API_KEY="YOUR_GEMINI_API_KEY"
```

### 3. Start Development Server
Boot the Express + Vite combined full-stack listener on port `3000`:
```bash
npm run dev
```
Open browser page: `http://localhost:3000`

### 4. Build Production Standalone
Compile both React and Node server types:
```bash
npm run build
npm start
```

---

## 🐳 Docker Deployment Setup
To run the platform securely quarantined inside lightweight Docker containers:

### 1. Create `/Dockerfile`
```dockerfile
# Use lightweight Node image
FROM node:20-alpine

# Set directory
WORKDIR /app

# Copy lock files and packages
COPY package*.json ./

# Install packages
RUN npm ci

# Copy full codebase
COPY . .

# Compile optimized static bundle and server.cjs
RUN npm run build

# Expose port (Nginx reverse gateway binds on 3000)
EXPOSE 3000

# Execute server
CMD ["npm", "start"]
```

### 2. Run Container Build
```bash
# Compile docker image
docker build -t phishforensic-suite:latest .

# Launch container on local port 3000
docker run -d --name phishforensics -p 3000:3000 -e GEMINI_API_KEY="your-key-here" phishforensic-suite:latest
```

---

## 🛡️ Presentation Tips for PPT/Viva Defense
When presenting to examiners or supervisors:
1. **The Ingress Pipeline Demonstration**: Inject the **Netflix Card Scam** academic threat. Highlight the automated triggers (unsecure HTTP redirect, low domain age, fail SPF badge). Shows the combined score rises to **Critical**.
2. **Explain the Hybrid Intelligence**: Mention that the ML weights understand *lexical content triggers* (like "restricted", "verify") in milliseconds, while the Gemini LLM performs *conceptual social engineering audits* and writes customized remediation steps. This demonstrates the master of both deterministic heuristics and semantic AI!
3. **Trigger Model Retraining Live**: Open the **ML Lab** tab, select 150 epochs, click *Re-Compile Model*, and walk the examiners through the declining log loss curve! Show them how the feature importance coefficient weighs are dynamically restructured. This guarantees top academic marks!
