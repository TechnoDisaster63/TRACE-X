# Enron false-alarm check

**Run:** 2026-09-23, TRACE-X branch `docs/readme-masterclass` (based on `main` d6c7a68).
**Question:** how often does TRACE-X raise a false alarm on real legitimate mail?
**Not tested here:** phishing detection. Enron is legitimate corporate mail.

## Data

- Corpus: CMU Enron Email Dataset, release `enron_mail_20150507.tar.gz` from https://www.cs.cmu.edu/~enron/
- Archive SHA-256: `b3da1b3fe0369ec3140bb4fbce94702c33b7da810ec15d718b3fadf5cd748ca7`
- 517,401 messages in the archive. Random sample of **5,000** drawn with `random.seed(26106)`. The exact file list is in [`enron_sample_files.txt`](enron_sample_files.txt).
- Messages are 1999-2002 business mail. They are treated as legitimate. A small number of spam or unwanted messages may exist in the corpus; they were not relabelled.

## Results

| Measure | Count | Rate (95% Wilson CI) |
|---|---:|---:|
| Messages analysed | 5,000 | 0 errors |
| Risk **HIGH** | 4 | 0.08% (0.03-0.21%) |
| Risk MEDIUM | 4,996 | 99.92% |
| Risk LOW | 0 | 0% |
| M18 advisory probability >= 0.5 | 56 | 1.12% (0.86-1.45%) |
| M18 advisory probability >= 0.9 | 6 | 0.12% (0.06-0.26%) |

Score: median 30, mean 30.09, 95th percentile 30. Raw summary: [`enron_sample_summary.json`](enron_sample_summary.json).

All 4 HIGH results were driven by an `http://` link whose host is a raw IP address.

## Why nearly every message is MEDIUM (30)

This Enron release has **no delivery headers**. None of the 5,000 sampled files has an `Authentication-Results` header, and all 5,000 fired "No Received headers present". Those missing-header findings (plus a Message-ID/From domain mismatch) add up to 30 points on every message.

What this means:

- Header forensics (M02-M05) **could not be tested** on this corpus. The MEDIUM rate reflects missing headers, not TRACE-X judging Enron mail suspicious.
- The HIGH rate tests the URL and content signals only.
- **Known weakness found:** every sampled message was classified `INFRASTRUCTURE_ABUSE`. That class should not fire just because headers are missing. This is recorded here and not yet fixed.

## Reproduce

```bash
curl -O https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz
mkdir -p /tmp/enron
tar xzf enron_mail_20150507.tar.gz -C /tmp/enron -T docs/evaluation/enron_sample_files.txt
python scripts/eval/enron_false_positive.py /tmp/enron docs/evaluation/enron_sample_files.txt /tmp/enron-out
```
