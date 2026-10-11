# 🎓 B.Tech Project Viva Voce Guide & FAQ
## Project: Internship Scam Detection and Risk Assessment System Using Machine Learning and NLP

This document contains 15 of the most probable questions an external examiner or project supervisor will ask during your final-year viva, along with concise, technically sound answers designed for a beginner to explain with confidence.

---

### Q1. What is the objective of your project?
**Answer:**  
The objective is to protect students and fresh graduates from fake job and internship scams by evaluating posting descriptions in real-time. It analyzes red flags (such as upfront fees, unrealistic stipends, and personal communication channels), calculates a calibrated risk score (0 to 100), and provides explainable warnings with actionable safety guidelines.

---

### Q2. Why did you choose a hybrid approach (Rules + ML) instead of using only Machine Learning?
**Answer:**  
- **Rule Engine:** Provides deterministic, immediate detection of critical, unambiguous scam signals (e.g., specific terms like "registration fee", "security deposit", or Telegram contacts) that must always trigger a warning regardless of phrasing.
- **Machine Learning (TF-IDF + Logistic Regression):** Captures subtle contextual patterns, vocabulary distributions, and generalized scam language that regex rules might miss.
- **Combining Both (Risk Fusion):** Reduces both false positives and false negatives, ensuring that the system is both robust against evasive phrasing and 100% explainable to the student.

---

### Q3. Which Machine Learning algorithm did you use, and why?
**Answer:**  
We used **Logistic Regression** paired with **TF-IDF Vectorization**.  
*Reasons:*
1. It is a linear probabilistic classifier that natively outputs calibrated probabilities (`predict_proba`) between 0.0 and 1.0, which integrates directly into our risk percentage scoring.
2. It performs exceptionally well on high-dimensional sparse text data.
3. It has fast training and inference speeds, low memory overhead, and avoids overfitting on small-to-medium text corpora.

---

### Q4. What is TF-IDF and how does it vectorize text?
**Answer:**  
TF-IDF stands for **Term Frequency - Inverse Document Frequency**:
- **Term Frequency (TF):** Measures how frequently a word appears in a specific document.
- **Inverse Document Frequency (IDF):** Penalizes common words across the entire dataset (like "the", "and") and assigns higher weights to distinctive, informative terms (like "stipend", "deposit", "telegram").
It converts unstructured raw text strings into a numerical feature matrix suitable for machine learning algorithms.

---

### Q5. What are n-grams, and why did you use `ngram_range=(1, 2)`?
**Answer:**  
An n-gram is a contiguous sequence of $n$ items from a given text:
- **Unigram ($n=1$):** Single words (e.g., "fee", "registration").
- **Bigram ($n=2$):** Two-word pairs (e.g., "registration fee", "no interview").
We used `ngram_range=(1, 2)` so the model captures critical multi-word contextual phrases like "registration fee" or "instant offer", which carry far more scam signal together than the words do individually.

---

### Q6. What are the key rules implemented in your rule-based engine?
**Answer:**  
The expanded rule engine in `scam_checker.py` checks for:
1. **Upfront Payment Demands (30 pts):** "registration fee", "training fee", "security deposit", "kit fee".
2. **Unrealistic Stipends (20 pts):** "₹50,000 per month", "earn huge", "earn 50k for freshers".
3. **Guaranteed Selection (15 pts):** "100% placement", "guaranteed job", "guaranteed internship".
4. **No Interview / Direct Offer (15 pts):** "no interview", "direct selection", "instant offer letter".
5. **Urgent Language (10 pts):** "immediate joining", "urgent requirement", "limited seats".
6. **Personal Email Domains (10 pts):** `@gmail.com`, `@yahoo.com` instead of company domains.
7. **Chat-Only Contact (15 pts):** "WhatsApp only", "contact on WhatsApp", "DM on Telegram".
8. **Vague Identity (10 pts):** "confidential client", "reputed MNC without name".

---

### Q7. How does the URL and Email checker work without external APIs?
**Answer:**  
In `url_checker.py`, we perform local heuristic analysis using Python standard libraries (`re` and `urllib.parse`):
1. **Missing HTTPS:** Flags URLs beginning with unencrypted `http://`.
2. **Raw IP Address URLs:** Regex identifies URLs hosted directly on IP addresses (e.g., `http://192.168.1.100`), commonly used in temporary phishing hosts.
3. **Excessive Length:** Flags URLs longer than 75 characters, which often mask redirection tokens.
4. **Suspicious Terms:** Scans for keywords like `free`, `bonus`, `bit.ly`, `tinyurl`, `wa.me`.
5. **Personal Domains:** Extracts email domains and flags personal webmail (`gmail.com`, `yahoo.com`, `outlook.com`) where a corporate custom domain is expected.

---

### Q8. How is the final combined risk score calculated?
**Answer:**  
The final risk score uses a **50/50 weighted combination formula**:
$$\text{Final Risk Score} = \text{round}(0.5 \times \text{Rule Score} + 0.5 \times (\text{ML Scam Probability} \times 100))$$
The score is clamped between 0 and 100 and mapped into 4 clear risk bands:
- **0 – 25:** Low Risk (Legitimate characteristics)
- **26 – 50:** Moderate Risk (Exercise caution, verify credentials)
- **51 – 75:** High Risk (Multiple red flags present)
- **76 – 100:** Very High Risk (Severe red flags; upfront payment or instant WhatsApp hiring detected)

---

### Q9. Why does your system state "High Risk" instead of saying "Definitely a Scam"?
**Answer:**  
In cybersecurity and ethical AI, automated systems must never make absolute legal claims of fraud because of the possibility of edge cases or false positives. Instead, providing an explainable risk rating (*"High Risk"*) alongside specific identified evidence allows the student to understand *why* caution is needed while making an informed, safe decision.

---

### Q10. How is user authentication implemented, and how are passwords stored?
**Answer:**  
- Authentication uses **Flask sessions** to maintain state across HTTP requests.
- Passwords are **never stored in plain text**. They are hashed using **Werkzeug's `generate_password_hash`** (which uses secure cryptographic salt and key-stretching hashing algorithms like `scrypt` or `pbkdf2:sha256`).
- Verification is done through `check_password_hash`.
- Checks in `history.db` are tagged with the logged-in user's `user_id` so each student only accesses their own scan history.

---

### Q11. How is SQLite database structured in your project?
**Answer:**  
The SQLite database `history.db` has two relational tables:
1. **`users` Table:** Stores `id`, `username`, `password_hash`, and `created_at`.
2. **`checks` Table:** Stores `id`, `user_id` (foreign key), `time`, `snippet`, `score`, `level`, `rule_score`, `ml_prob`, `reasons`, `url_warnings`, and `full_text`.
We also implemented automatic schema migration in `init_db()` so any legacy database automatically adds missing columns without errors.

---

### Q12. What evaluation metrics did you use for the ML model?
**Answer:**  
We evaluated the model on a 20% test holdout using:
- **Accuracy:** Total correct predictions divided by total samples ($\frac{TP + TN}{TP + TN + FP + FN}$).
- **Precision:** Of all postings flagged as scams, how many were truly scams ($\frac{TP}{TP + FP}$).
- **Recall (Sensitivity):** Of all actual scams, how many were successfully detected ($\frac{TP}{TP + FN}$).
- **F1-Score:** The harmonic mean of Precision and Recall ($2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$).
- **Confusion Matrix:** A $2 \times 2$ table showing True Negatives, False Positives, False Negatives, and True Positives.

---

### Q13. In scam detection, is Precision or Recall more important, and why?
**Answer:**  
**Recall is more critical.**  
- A *False Positive* (classifying a legitimate internship as suspicious) causes minor inconvenience (the student will manually verify the company).
- A *False Negative* (failing to detect a scam) can cause severe harm: the student may lose ₹2,000–₹5,000 to fraudsters and compromise their identity.  
Therefore, maximizing Recall ensures that virtually no scam slips through undetected.

---

### Q14. How did you handle the dataset for training?
**Answer:**  
Because external job scam datasets (such as the EMSCAD dataset) focus mainly on US full-time jobs, we developed an automated synthetic generator (`generate_synthetic_dataset` in `ml_model.py`) that produces **600 realistic internship postings tailored to the Indian context**:
- Contains Indian currency amounts (₹8,000 stipend vs ₹50,000 fake data-entry claims).
- Features typical Indian payment scam modalities (registration fees, laptop kit deposits).
- Reflects authentic recruitment stacks (B.Tech CS/IT, HackerRank, GitHub, technical interviews, PPOs).
- Saved in standard CSV format (`data/fake_job_postings.csv`) with balanced 50:50 class distribution.

---

### Q15. What are the limitations and future enhancements for this project?
**Answer:**  
- **Limitations:**
  - Evaluates plain text only; cannot directly inspect image attachments or PDF offer letters without OCR.
  - Currently runs locally without live WHOIS domain age lookups.
- **Future Enhancements:**
  1. Add **Tesseract OCR / PDF parser** to analyze scanned offer letters and appointment letters.
  2. Implement a **Chrome / Web Extension** that automatically scans internship postings directly on LinkedIn, Internshala, and Naukri.
  3. Explore fine-tuned transformer models (like DistilBERT) for even deeper semantic nuance.

---

### 💡 Quick Viva Tip for the Student:
When the examiner asks you to demonstrate the project:
1. Open `http://127.0.0.1:5000`.
2. Click **"🚨 Load Scam Example"** and click **"Assess Scam Risk"**. Show the examiner the **Very High Risk** badge, the breakdown of Rule Score vs ML probability, the detected warning items, and the student safety advice box.
3. Click **"✅ Load Legitimate Example"** and run it to demonstrate that authentic postings receive a **Low Risk** badge.
4. Show the **Dashboard** (`/dashboard`) to show the risk distribution bar chart and the **Confusion Matrix & ML metrics**.
5. Show **Report History** (`/history`) and demonstrate deleting a record.
6. Open your terminal and show `pytest -v` passing all 22 tests.
