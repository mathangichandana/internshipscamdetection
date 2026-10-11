import os
import random
import re
import numpy as np
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DATA_FILE = os.path.join(DATA_DIR, "fake_job_postings.csv")
MODEL_FILE = os.path.join(os.path.dirname(__file__), "model.joblib")
METRICS_FILE = os.path.join(os.path.dirname(__file__), "model_metrics.joblib")

# Global reference for cached model pipeline and metrics
_PIPELINE = None
_METRICS = None


# Generates a realistic synthetic dataset of Indian internship postings if external data is absent.
def generate_synthetic_dataset(output_path, count=600):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    random.seed(42)

    scam_roles = [
        "Data Entry Operator Intern",
        "Online Form Filling Intern",
        "Part-Time Typing Intern",
        "Copy Paste Work Intern",
        "Social Media Ad Clicker Intern",
        "Captcha Solver Intern",
        "SMS Sending Work from Home Intern",
        "Virtual Assistant Intern (No Skills)",
        "Back-Office Document Processor",
        "Easy Chat Support Executive Intern",
    ]

    scam_pay = [
        "₹40,000 per month",
        "₹50,000 per month",
        "₹60,000 per month",
        "₹75,000 per month",
        "₹1,500 daily payout",
        "₹2,500 per day guaranteed",
        "Earn ₹55,000/month work from home",
        "₹80,000 monthly for freshers",
    ]

    scam_fees = [
        "Pay ₹1,000 registration fee to confirm your slot.",
        "Refundable security deposit of ₹2,500 required for software license.",
        "One-time laptop delivery and kit fee of ₹1,800 required.",
        "Mandatory document verification and ID card processing fee ₹999.",
        "Submit ₹3,000 caution deposit before joining (100% refundable).",
        "Registration charge ₹1,499 for company badge and portal access.",
        "Training and onboarding material fee of ₹2,000 only.",
    ]

    scam_contacts = [
        "Contact HR Priya on WhatsApp: +91-9876543210.",
        "DM on Telegram @careers_instant_jobs to get offer letter.",
        "Send your resume to hr.recruitment2026@gmail.com.",
        "WhatsApp your name and college to +91-9123456780 immediately.",
        "Email direct to placement.offers2026@yahoo.com.",
        "Connect on Telegram group @remote_interns_india.",
    ]

    scam_urgencies = [
        "Immediate joining, only 3 seats remaining! Hurry!",
        "Offer valid only for next 24 hours. Apply right now!",
        "Urgent requirement! Limited slots available for freshers.",
        "Direct hiring, apply today before registrations close!",
    ]

    scam_no_interviews = [
        "No interview required. Direct selection based on application.",
        "100% guaranteed job placement with instant offer letter.",
        "No technical test or prior experience needed. Direct hiring.",
        "Guaranteed internship selection with zero qualification screening.",
    ]

    scam_links = [
        "Apply online: http://192.168.1.100/apply-free-job-form",
        "Submit details at http://tinyurl.com/fast-intern-payout",
        "Register now at http://45.33.22.11/careers-instant-form",
        "Form link: http://bit.ly/guaranteed-internship-selection",
    ]

    # Legitimate internship building blocks
    legit_roles = [
        "Python / Django Developer Intern",
        "Frontend React.js Developer Intern",
        "Data Science & Analytics Intern",
        "Machine Learning Research Intern",
        "Backend Node.js / Express Intern",
        "Android / Flutter Mobile Developer Intern",
        "UI/UX Design Intern (Figma)",
        "Digital Marketing & SEO Intern",
        "DevOps & Cloud Engineering Intern",
        "QA / Software Testing Automation Intern",
        "Content Marketing & Technical Writing Intern",
        "Cybersecurity Analyst Intern",
    ]

    legit_companies = [
        "CloudScale Technologies",
        "Innovatech Solutions Pvt Ltd",
        "FinEdge Analytics",
        "Zenith AI Labs",
        "NexGen Software Systems",
        "AlphaCore Data Systems",
        "Hyperion Digital Media",
        "VectorByte Infotech",
    ]

    legit_stipends = [
        "Stipend: ₹10,000 - ₹15,000 per month depending on technical interview.",
        "Stipend: ₹18,000 per month with performance bonuses.",
        "Stipend: ₹12,000 - ₹20,000 per month based on technical skill evaluation.",
        "Stipend: ₹25,000 per month with Pre-Placement Offer (PPO) opportunity.",
        "Stipend: ₹8,000 - ₹14,000/month along with verified course certificate.",
        "Competitive monthly stipend of ₹15,000 plus flexible working hours.",
    ]

    legit_processes = [
        "Selection process: Resume screening, online coding test on HackerRank, followed by 1 technical interview round.",
        "Hiring rounds: Assignment submission, code review on GitHub, and video interview with lead engineers.",
        "Selection involves: Technical assessment in Python/Data Structures and a managerial discussion.",
        "Applicants will undergo resume review and a technical interview discussing past projects and git repositories.",
    ]

    legit_requirements = [
        "Requirements: Final year B.Tech/BCA/MCA students proficient in OOP, Git, and database fundamentals.",
        "Qualifications: Strong problem-solving abilities, familiarity with REST APIs, and hands-on academic projects.",
        "Eligibility: Basic knowledge of Python, SQL, and data analysis libraries like Pandas and NumPy.",
        "Ideal candidate: Passionate learner with solid understanding of web development and responsive UI design.",
    ]

    records = []
    half = count // 2

    # Generate Scam Postings (label = 1)
    for i in range(half):
        role = random.choice(scam_roles)
        pay = random.choice(scam_pay)
        fee = random.choice(scam_fees)
        contact = random.choice(scam_contacts)
        urgency = random.choice(scam_urgencies)
        no_int = random.choice(scam_no_interviews)
        link = random.choice(scam_links) if random.random() > 0.3 else ""

        templates = [
            f"{urgency} {role} wanted. {no_int} {pay}. {fee} {contact} {link}",
            f"Opportunity for students! {role}. {pay}. Work from home. {fee} {no_int} {contact}",
            f"{role} opening. {no_int} Earn up to {pay}. {fee} {urgency} Contact: {contact}",
            f"Reputed MNC hiring for {role}. {pay} guaranteed. {fee} {no_int} {urgency} Reach out: {contact} {link}",
        ]
        text = random.choice(templates).strip()
        records.append({"text": text, "label": 1})

    # Generate Legitimate Postings (label = 0)
    for i in range(half):
        role = random.choice(legit_roles)
        company = random.choice(legit_companies)
        stipend = random.choice(legit_stipends)
        process = random.choice(legit_processes)
        req = random.choice(legit_requirements)
        domain = company.lower().replace(" ", "").replace("pvt", "").replace("ltd", "")
        email = f"careers@{domain}.com"
        portal = f"https://{domain}.com/careers"

        templates = [
            f"{company} is hiring for a {role} in Bengaluru / Remote. {req} {process} {stipend} Apply via official career portal: {portal} or send your GitHub profile to {email}. We never charge any fee for recruitment.",
            f"Internship Opportunity: {role} at {company}. Duration: 3-6 months. {req} {stipend} {process} Official inquiries: {email}. Transparent merit-based hiring process with zero application fees.",
            f"{role} - {company}. We are seeking motivated engineering students. {req} {process} {stipend} Opportunity for full-time PPO conversion. Official website: {portal}. Free application process.",
            f"Join {company} as a {role}. Work alongside senior developers on production systems. {req} {stipend} {process} Apply at {portal} or contact {email}. Legitimate Equal Opportunity Employer.",
        ]
        text = random.choice(templates).strip()
        records.append({"text": text, "label": 0})

    # Shuffle records
    random.shuffle(records)
    df = pd.DataFrame(records)
    df.to_csv(output_path, index=False)
    print(f"Generated {len(df)} synthetic labelled internship postings at: {output_path}")
    return df


# Loads existing dataset or generates synthetic one, trains TF-IDF + Logistic Regression, and evaluates metrics.
def train_model(dataset_path=None, model_path=None):
    if dataset_path is None:
        dataset_path = DATA_FILE
    if model_path is None:
        model_path = MODEL_FILE

    if os.path.exists(dataset_path):
        df = pd.read_csv(dataset_path)
        # Adapt column names if standard external dataset like Kaggle fake_job_postings is used
        if "fraudulent" in df.columns and "description" in df.columns:
            df = df.rename(columns={"description": "text", "fraudulent": "label"})
        elif "is_scam" in df.columns:
            df = df.rename(columns={"is_scam": "label"})
    else:
        df = generate_synthetic_dataset(dataset_path, count=600)

    # Clean missing values
    df["text"] = df["text"].fillna("").astype(str)
    df["label"] = df["label"].astype(int)

    X = df["text"]
    y = df["label"]

    # Stratified train-test split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    # Pipeline: TF-IDF vectorizer + Logistic Regression
    pipeline = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    ngram_range=(1, 2),
                    max_features=4000,
                    sublinear_tf=True,
                    stop_words="english",
                ),
            ),
            (
                "clf",
                LogisticRegression(
                    C=1.0, max_iter=1000, solver="liblinear", random_state=42
                ),
            ),
        ]
    )

    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    # Performance metrics
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred, zero_division=0))
    rec = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "accuracy": round(acc, 4),
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "f1": round(f1, 4),
        "confusion_matrix": cm,
        "test_samples": len(y_test),
        "train_samples": len(X_train),
    }

    # Save trained pipeline and metrics to disk
    joblib.dump(pipeline, model_path)
    joblib.dump(metrics, METRICS_FILE)

    global _PIPELINE, _METRICS
    _PIPELINE = pipeline
    _METRICS = metrics

    print("================ ML MODEL TRAINING RESULTS ================")
    print(f"Accuracy : {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall   : {rec * 100:.2f}%")
    print(f"F1-Score : {f1 * 100:.2f}%")
    print(f"Confusion Matrix (TN, FP / FN, TP):")
    print(np.array(cm))
    print(f"Model saved to: {model_path}")
    print("===========================================================")

    return pipeline, metrics


# Loads model from disk or trains a new one if not yet built.
def load_or_train_model():
    global _PIPELINE, _METRICS
    if _PIPELINE is not None and _METRICS is not None:
        return _PIPELINE, _METRICS

    if os.path.exists(MODEL_FILE) and os.path.exists(METRICS_FILE):
        try:
            _PIPELINE = joblib.load(MODEL_FILE)
            _METRICS = joblib.load(METRICS_FILE)
            return _PIPELINE, _METRICS
        except Exception:
            pass

    return train_model()


# Predicts the scam probability (0.0 to 1.0) for a given job/internship posting text.
def predict_scam_probability(text):
    if not text or not isinstance(text, str) or not text.strip():
        return 0.0

    pipeline, _ = load_or_train_model()
    # Predict probability for class 1 (scam)
    probs = pipeline.predict_proba([text])
    scam_prob = float(probs[0][1])
    return scam_prob


# Retrieves the stored performance evaluation metrics of the trained ML model.
def get_model_metrics():
    _, metrics = load_or_train_model()
    return metrics


# Standalone training and verification entry point
if __name__ == "__main__":
    pipe, metrics = load_or_train_model()

    scam_sample = (
        "Urgent! Work from home typing intern wanted. Earn ₹50,000 per month. "
        "Pay ₹1,500 registration fee. No interview, direct joining. Contact on WhatsApp +91-9876543210."
    )
    legit_sample = (
        "CloudScale Technologies is hiring a Python Developer Intern. B.Tech CS students with Git and SQL knowledge. "
        "Stipend ₹15,000/month. Technical interview round on Google Meet. Apply at https://cloudscale.in/careers. No fee."
    )

    print("\nTest Scam Sample Probability:", predict_scam_probability(scam_sample))
    print("Test Legit Sample Probability:", predict_scam_probability(legit_sample))
