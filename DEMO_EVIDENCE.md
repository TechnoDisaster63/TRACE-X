# TRACE-X SIH demo evidence

## Judge flow

1. Launch `python demo.py` and confirm the page says LOOPBACK / OFFLINE.
2. Run the legitimate scenario to establish the low-risk baseline.
3. Run PayPal look-alike phishing with trusted domain `paypal.com`; open the linked evidence rows and compare severity, observation status, source reliability and analytic confidence.
4. Point out that authentication claims say `REPORTED_UNVERIFIED` and `independently verified = false` unless an explicit trusted receiver boundary was supplied.
5. Run the BEC scenario; show `executable=false`, the human-approval requirement, and counterfactual out-of-band verification.
6. Show the case package as VALID, then explain that its manifest detects local tampering but is not a signature or legal attestation.
7. Run `python cli.py campaign test_data/campaign` to demonstrate batch-only correlation.

## Evidence to capture for the pitch

- Full console screen after the phishing scenario.
- One provenance row showing evidence ID, retained origin, and source locator.
- Score explanation beside the non-executable recommendation.
- VALID package verification plus the explicit integrity disclaimer.
- CLI campaign output showing three investigations and one batch-only campaign.

Do not claim live threat intelligence, URL fetching, attachment execution, independent SPF/DKIM/DMARC verification, autonomous enforcement, production deployment, calibrated ML probability, persistent campaign memory, or legal chain of custody.
