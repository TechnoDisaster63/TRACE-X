# M18 - Offline ML phishing-language signal

M18 adds one advisory evidence signal to an investigation: a calibrated phishing-language probability plus the highest positive coefficient-weighted TF-IDF terms present in that email. It runs locally from the bundled `tracex_ml_v2.pkl`; it performs no network request. The output is not a verdict, is never executable, causes no automatic action, and does not override the deterministic TRACE-X rule engine.

## Training and evaluation boundary

The supplied model was trained on the public Nazario `phishing0.mbox` / `phishing1.mbox` phishing corpus and SpamAssassin `easy_ham`. These are historical, roughly 2005-2007-era corpora. Its held-out 648-sample test split reported phishing precision 1.00, recall 0.98, and F1 0.99. Those are test-set-only results on these corpora, not a claim of field accuracy, production readiness, or performance on current mail.

Training and inference use the same cleaner, in this order:

1. strip HTML tags with `<[^>]+>`;
2. `html.unescape` entities;
3. replace `http://` and `https://` URLs with ` URL `;
4. normalize whitespace.

The pickle records this as `strip_html+unescape+url_norm`. A metadata mismatch makes the signal unavailable rather than silently applying a different transform.

## Optional dependency and graceful degradation

Install the pinned optional runtime with:

```bash
python -m pip install -r requirements-ml.txt
```

If scikit-learn is absent, the pickle is missing or unreadable, or its expected keys/cleaner metadata do not match, M18 returns one informational `ML phishing-language signal unavailable` finding. The pipeline continues and never invents a probability.

Pickle artifacts must be treated as executable Python serialization and replaced only from a trusted source. The bundled artifact is the user-supplied trained model recorded for this module.
