# 🛡️ Internship Scam Detection and Risk Assessment System

> **B.Tech Final-Year Project**  
> *Using Machine Learning, Natural Language Processing (NLP), and Rule-Based Risk Fusion*

---

## 📌 Project Overview
College students and fresh graduates are increasingly targeted by fraudulent internship postings on platforms like LinkedIn, WhatsApp, and Telegram. These scams often trick students into paying upfront "registration fees", "training fees", or "security deposits", promising unrealistic stipends (e.g., ₹50,000/month for simple data entry) and "direct selection without interview".

**InternGuard** is a hybrid risk assessment system that combines:
1. **Rule-Based NLP Engine:** Regex-driven detection of critical red flags (upfront payment demands, unrealistic salary, guaranteed jobs, no interview, urgency, personal emails, WhatsApp-only contacts).
2. **URL & Email Security Inspector:** Heuristic offline inspection of links (missing HTTPS, raw IP addresses, excessive URL length, scam keywords) and recruiter email domains.
3. **Machine Learning Classifier:** TF-IDF n-gram vectorization combined with Logistic Regression trained on a curated dataset of Indian internship postings (amounts in ₹).
4. **Weighted Risk Fusion:** Combines deterministic rules (50%) and ML probability (50%) into a 0–100 risk score with explainable warnings and student safety advice.

---

## 🧱 Project Directory Structure
```text
scam_project/
│
├── app.py                   # Main Flask application (routes, auth, SQLite integration)
├── scam_checker.py          # Expanded regex rule engine (check(text) -> score, level, reasons)
├── url_checker.py           # Offline URL and email domain security analyzer
├── ml_model.py              # Synthetic dataset generator, TF-IDF + Logistic Regression, joblib model
├── risk_assessor.py         # Hybrid score aggregator (combines Rules + URLs + ML probability)
├── history.db               # SQLite database storing users and per-user check histories
├── model.joblib             # Serialized trained scikit-learn pipeline
├── model_metrics.joblib     # Serialized evaluation metrics (Accuracy, Precision, Recall, F1)
├── requirements.txt         # Project dependencies
├── README.md                # Project documentation and setup guide
├── VIVA_NOTES.md            # 15 Viva questions with concise answers for B.Tech examination
│
├── data/
│   └── fake_job_postings.csv # Labelled dataset (600 Indian internship postings, ₹ amounts)
│
├── templates/               # Responsive HTML templates
│   ├── layout.html          # Base layout with navbar, flash messages, and footer
│   ├── index.html           # Scanner interface with sample loading & result card
│   ├── history.html         # Report history table with delete & clear options
│   ├── dashboard.html       # Analytics dashboard with CSS bar chart & ML metrics
│   ├── login.html           # User sign-in interface
│   └── register.html        # User registration interface
│
├── static/
│   └── style.css            # Responsive CSS stylesheet with risk badge themes
│
└── tests/                   # Pytest test suite (22 unit & integration tests)
    ├── test_scam_project.py # 18 tests for Rules, URL checker, Email checker, and ML model
    └── test_app.py          # Integration tests for Flask endpoints and auth flow
```

---

## ⚙️ How It Works (System Architecture)

```
                            [ Internship Posting Text ]
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 │                       │                       │
                 ▼                       ▼                       ▼
     [ 1. Expanded Rules ]     [ 2. URL/Email Inspector ]  [ 3. ML Model (TF-IDF) ]
     - Upfront fees            - Missing HTTPS             - Text Tokenization
     - Unrealistic salary (₹)  - Raw IP address links       - TF-IDF N-grams (1,2)
     - Guaranteed jobs         - Excessive URL length      - Logistic Regression
     - Direct hiring           - Personal emails (@gmail)  - Probabilistic scoring
     (Rule Score: 0-100)       (Extracted Warnings)        (ML Probability: 0-100%)
                 │                       │                       │
                 └───────────────────────┼───────────────────────┘
                                         ▼
                             [ 4. Weighted Risk Fusion ]
                   Final Score = round(0.5 * Rule + 0.5 * ML)
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 ▼                       ▼                       ▼
           [ 0 - 25 ]              [ 26 - 50 ]             [ 51 - 75 ]       [ 76 - 100 ]
            Low Risk              Moderate Risk             High Risk       Very High Risk
                                         │
                                         ▼
                            [ Explainable Result Card ]
                 - Categorized Warning Signs
                 - URL & Recruiter Details
                 - Student Actionable Safety Advice
                 - Saved to SQLite (Per User)
```

---

## 🚀 Setup & Execution (Windows / Python 3.14)

### 1. Prerequisites
Ensure Python 3.10+ (or Python 3.14) is installed on your Windows machine.

### 2. Install Required Dependencies
Open PowerShell or Command Prompt, navigate to the `scam_project` directory, and run:
```powershell
pip install -r requirements.txt
```

### 3. Train ML Model and Generate Dataset (Optional - Auto runs on startup)
The ML model trains automatically on first run, or you can run it directly:
```powershell
python ml_model.py
```
This creates `data/fake_job_postings.csv`, trains the TF-IDF + Logistic Regression pipeline, prints evaluation metrics, and saves `model.joblib`.

### 4. Run the Web Application
```powershell
python app.py
```
Open your browser and navigate to:  
👉 **http://127.0.0.1:5000**

---

## 🧪 Running Unit Tests
The project includes **22 comprehensive unit and integration tests** built with `pytest`.

Run the test suite using:
```powershell
pytest -v
```

All 22 tests verify:
- Rule engine regex patterns (payment words, salary, guaranteed job, no interview, urgency, etc.)
- URL checker (missing HTTPS, IP hosts, long URLs, suspicious terms)
- Email domain checker (personal vs corporate domain identification)
- ML model prediction bounds and scam vs legitimate probability separation
- Full risk assessor output structure and explainability constraints
- Flask endpoints, user authentication, sessions, and dashboard metrics

---

## 📸 Interface Walkthrough (Screenshots Section)

### 1. Main Scanner (`/`)
Allows pasting any job/internship description. Includes **"⚡ Quick Samples"** buttons:
- **🚨 Load Scam Example:** Pre-fills a typical scam asking for ₹1,500 registration fee and WhatsApp contact.
- **✅ Load Legitimate Example:** Pre-fills a genuine software engineering internship posting with formal interview rounds and zero fees.

```
┌────────────────────────────────────────────────────────────────────────┐
│ 🛡️ InternGuard ML         Scanner   Dashboard   Report History   [User]│
├────────────────────────────────────────────────────────────────────────┤
│ 🔍 Analyze Internship Posting                                          │
│ ⚡ Quick Samples: [🚨 Load Scam Example] [✅ Load Legitimate Example]    │
│                                                                        │
│ ┌────────────────────────────────────────────────────────────────────┐ │
│ │ URGENT HIRING: Work from Home Data Entry Internship!               │ │
│ │ Earn ₹50,000 per month. Pay ₹1,500 registration and laptop fee...  │ │
│ └────────────────────────────────────────────────────────────────────┘ │
│ [🛡️ Assess Scam Risk]                                                  │
└────────────────────────────────────────────────────────────────────────┘
```

### 2. Explainable Result Card
Displays risk badge, metric cards, warning reasons, and student safety advice:
```
┌────────────────────────────────────────────────────────────────────────┐
│ Assessment Outcome: [ VERY HIGH RISK ]           Combined Score: 81/100│
├────────────────────────────────────────────────────────────────────────┤
│  Rule Engine Score      ML Model Probability     Final Risk Assessment │
│       75 / 100                 86.0 %                  81 / 100        │
├────────────────────────────────────────────────────────────────────────┤
│ ⚠️ Warning Signs & Anomalies Identified                                │
│ 🚩 Requests upfront payment or deposit (registration/training/kit fee) │
│ 🚩 Unrealistic salary or stipend claim for an internship role          │
│ 🚩 Directs communication solely via WhatsApp or Telegram messaging     │
│ 🚩 Missing HTTPS: Link uses insecure HTTP protocol.                    │
│ 🚩 IP Address Host: Link uses a raw IP address instead of domain.      │
├────────────────────────────────────────────────────────────────────────┤
│ 🛡️ Student Safety Advice & Next Steps                                  │
│ ✓ CRITICAL: Under no circumstances transfer money for an internship.   │
│ ✓ Verify company on official website and MCA portal.                   │
│ ✓ Legitimate companies conduct technical interviews or assessments.    │
└────────────────────────────────────────────────────────────────────────┘
```

### 3. Risk Analytics Dashboard (`/dashboard`)
Shows live check counts, a clean CSS bar chart across the 4 risk tiers, and ML model performance metrics (Accuracy, Precision, Recall, Confusion Matrix).

### 4. Report History (`/history`)
Presents a per-user audit log of past scans with snippet, timestamp, rule score, ML probability, risk badge, and a **🗑️ Delete** button for each record.

---

## 🔒 Security & Privacy Features
- **Offline Inspection:** No external network requests or third-party APIs are called during URL/email checks.
- **Secure Password Hashing:** User passwords are encrypted with Werkzeug (`scrypt`/`pbkdf2`) before SQLite storage.
- **Explainable Language:** The system explicitly avoids absolute assertions like *"definitely a scam"*, using evidence-backed risk classifications like *"High Risk"* alongside identified signals.
