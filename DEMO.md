# SecretTrace AI — Hackathon Demo Script

This guide outlines a step-by-step path to present **SecretTrace AI** in a 5 to 10-minute hackathon presentation.

---

## 1. Introduction: The Hook (1 minute)
1. **Explain the Pain:** Naive secret scanners flag generic string matches like `API_KEY="your-api-key-here"`, generating false positives that waste developers' time. At the same time, if a developer commits a secret and deletes it in a later commit, basic scanners miss it, leaving the secret exposed in Git history.
2. **Introduce SecretTrace AI:** *"Find the secrets Git forgot."* It scans the complete Git history, filters out placeholders/test code using a hybrid classifier, tracks the provenance lifecycle of every secret, and verifies them safely.

---

## 2. Launch the Platform (1 minute)
* Launch the backend and frontend locally or using Docker Compose:
  ```bash
  docker compose up --build
  ```
* Open the **Dashboard UI** at [http://localhost:5173](http://localhost:5173).
* Note the clean, dark cybersecurity theme and the statistics cards showing scanned repositories and alert counts.

---

## 3. Run the Demo Scan (2 minutes)
1. Navigate to the **Scan Repository** tab.
2. The Repository path is preloaded with `fixtures/demo_repo` (created by our synthetic history generator script).
3. Select **Full Git History** mode and enable **Online Validation**.
4. Click **Launch SecretTrace Scan**.
5. Draw attention to the **Console Logger**: it displays live crawler metrics (cloning, commit enumeration, candidate extraction, and classifier scoring).

---

## 4. Explore Findings & Explainable AI (2 minutes)
1. Go to the **Findings** tab. You will see 3 distinct categories of findings:
   * **Stripe Secret Key (CRITICAL):** Classified as `REAL_SECRET` because of high entropy, valid credential format, and production context. It was committed in parent log and later deleted. Note the status: **DELETED IN HIST**.
   * **Stripe Test Key (LOW):** Classified as `TEST_FIXTURE` because it has the `sk_test_` prefix and is located in the test directory.
   * **AWS Access Key ID Placeholder (INFO):** Classified as a `PLACEHOLDER` because it contains the value `"YOUR_AWS_ACCESS_KEY_ID_HERE"`.
2. Click the **Stripe Secret Key** finding to open the details:
   * **Explainable AI Matrix:** Point to the explanation cards showing exactly why it got its score (e.g. `+15: Valid Stripe live secret key format`, `-0: No placeholder keywords`). This is crucial for developer trust!

---

## 5. Provenance Timeline & Code Context (2 minutes)
1. Look at the **Git Provenance Timeline** on the details pane:
   * Node 1: `INTRODUCED` by Author in Commit X (integrating Stripe gateway) inside `app_config.py`.
   * Node 2: `DELETED` in Commit Y (Oops! Developer removed it, but it remains in Git's object history).
2. Point out the **Code Context Snippet**: it shows the exact line of code containing the secret, with 3 lines of surrounding code as context to help triage. Note that the secret value is securely masked (e.g., `sk_live_51N2x••••••••tuvw`) on screen.

---

## 6. Safe Online Validation & Benchmark (1 minute)
1. On the Stripe secret finding, click **Check API**. Explain that the backend safely checks the key dynamically against Stripe's API and returns the validity, without ever storing the plaintext key in our database.
2. Navigate to the **Benchmarks** tab:
   * Explain that we ran a 500-instance evaluation suite (100 real keys, 100 placeholders, 100 tests, 100 docs, 100 random strings).
   * Show that SecretTrace AI achieved an **F1-Score of 86.9%** (vs 58.7% for regular regex) and reduced the **False Positive Noise Rate from 35.2% to just 3.0%** (a 91% reduction in developer noise!).
