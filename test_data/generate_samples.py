"""
Generates safe SYNTHETIC .eml files for TRACE-X testing.
No real malicious payloads. All domains/IPs are fictional/reserved-range.
Run: python test_data/generate_samples.py
"""
import os

BASE = os.path.dirname(__file__)


def write(path, content: str):
    full = os.path.join(BASE, path)
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w", encoding="utf-8", newline="\r\n") as f:
        f.write(content)
    print(f"wrote {full}")


# 1. Legitimate email -------------------------------------------------------
write("legitimate/legit_newsletter.eml", """From: "Acme Newsletter" <news@acme-corp.example>
To: alice@example.com
Subject: Your October Newsletter
Date: Mon, 05 Oct 2026 09:00:00 +0000
Message-ID: <news-2026-10-05@acme-corp.example>
Reply-To: news@acme-corp.example
Return-Path: <news@acme-corp.example>
Received: from mail.acme-corp.example (mail.acme-corp.example [198.51.100.10])
    by mx.example.com with ESMTP id abc123; Mon, 05 Oct 2026 08:59:50 +0000
Authentication-Results: mx.example.com; spf=pass smtp.mailfrom=acme-corp.example; dkim=pass header.d=acme-corp.example; dmarc=pass header.from=acme-corp.example
Content-Type: text/plain; charset="utf-8"

Hi Alice,

Here's what's new at Acme this month. Visit https://acme-corp.example/news for details.

Thanks,
Acme Team
""")

# 2. Phishing email -----------------------------------------------------
write("phishing/phishing_paypal_lookalike.eml", """From: "PayPal Security" <service@paypa1-verify.com>
To: victim@example.com
Subject: Your account has been limited - Action Required
Date: Tue, 06 Oct 2026 03:14:00 +0000
Message-ID: <8f3ac2@paypa1-verify.com>
Reply-To: recover@paypa1-verify.com
Return-Path: <bounce@paypa1-verify.com>
Received: from unknown (203.0.113.55) by mx.example.com; Tue, 06 Oct 2026 03:13:55 +0000
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=paypa1-verify.com; dkim=none; dmarc=fail header.from=paypa1-verify.com
Content-Type: text/html; charset="utf-8"

<html><body>
<p>Dear Customer,</p>
<p>We detected unusual activity. Please <a href="http://paypa1-verify.com.secure-login.info/verify?acct=1234&token=xyz">verify your account</a> immediately or it will be suspended.</p>
<p>PayPal Security Team</p>
</body></html>
""")

# 3. Fake CEO / BEC -------------------------------------------------------
write("bec/bec_ceo_wire_request.eml", """From: "John Carter (CEO)" <john.carter@company.com>
To: finance@company.com
Subject: Urgent wire transfer
Date: Wed, 07 Oct 2026 14:20:00 +0000
Message-ID: <bec001@company-support.com>
Reply-To: john.carter@company-support.com
Return-Path: <bounce@company-support.com>
Received: from smtp.external-relay.net (198.51.100.77) by mx.company.com; Wed, 07 Oct 2026 14:19:40 +0000
Authentication-Results: mx.company.com; spf=softfail smtp.mailfrom=company-support.com; dkim=none; dmarc=fail header.from=company.com
Content-Type: text/plain; charset="utf-8"

Hi,

I need you to process an urgent wire transfer of $48,500 to a new vendor today. This is time-sensitive, please handle quietly and confirm once done. Do not call me, I'm in meetings all day.

John Carter
CEO
""")

# 4. Reply-To attack ------------------------------------------------------
write("phishing/replyto_mismatch.eml", """From: billing@trustedvendor.com
To: ap@example.com
Subject: Updated invoice - payment details changed
Date: Thu, 08 Oct 2026 10:00:00 +0000
Message-ID: <inv-2026-1008@trustedvendor.com>
Reply-To: payments@trustedvendor-billing.net
Return-Path: <bounce@trustedvendor-billing.net>
Received: from mail.trustedvendor-billing.net (192.0.2.15) by mx.example.com; Thu, 08 Oct 2026 09:59:50 +0000
Authentication-Results: mx.example.com; spf=neutral smtp.mailfrom=trustedvendor-billing.net; dkim=fail; dmarc=none
Content-Type: text/plain; charset="utf-8"

Please note our banking details have changed. Reply to this email to confirm receipt before processing the attached invoice.
""")

# 5. Look-alike domain ------------------------------------------------
write("phishing/lookalike_domain.eml", """From: "Microsoft Account Team" <account-security@micros0ft-online.com>
To: user@example.com
Subject: Unusual sign-in activity detected
Date: Fri, 09 Oct 2026 05:45:00 +0000
Message-ID: <ms001@micros0ft-online.com>
Reply-To: account-security@micros0ft-online.com
Return-Path: <bounce@micros0ft-online.com>
Received: from mail.micros0ft-online.com (198.51.100.201) by mx.example.com; Fri, 09 Oct 2026 05:44:50 +0000
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/plain; charset="utf-8"

We noticed a new sign-in to your Microsoft account. If this wasn't you, secure your account at http://micros0ft-online.com/secure-login
""")

# 6. Authentication anomaly ---------------------------------------------
write("edge_cases/auth_anomaly_manipulated.eml", """From: ceo@company.com
To: finance@company.com
Subject: Re: Payment approval
Date: Sat, 10 Oct 2026 11:11:00 +0000
Message-ID: <auth001@company.com>
Received: from spoofed-relay (unknown [203.0.113.99]) by mx.company.com; Sat, 10 Oct 2026 11:10:55 +0000
Authentication-Results: mx.company.com; spf=pass (forged, injected by sender) smtp.mailfrom=company.com; dkim=pass header.d=company.com; dmarc=pass
X-Authentication-Results: this-header-is-fake; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset="utf-8"

Please approve the attached payment today.
""")

# 7. Suspicious URL ------------------------------------------------------
write("phishing/suspicious_url_ip_shortener.eml", """From: alerts@bank-secure-notice.com
To: user@example.com
Subject: Security alert: verify your login
Date: Sun, 11 Oct 2026 08:30:00 +0000
Message-ID: <sec001@bank-secure-notice.com>
Reply-To: alerts@bank-secure-notice.com
Return-Path: <bounce@bank-secure-notice.com>
Received: from mail.bank-secure-notice.com (203.0.113.201) by mx.example.com; Sun, 11 Oct 2026 08:29:50 +0000
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/plain; charset="utf-8"

Verify your login now: http://203.0.113.44/secure/verify-account-login-confirm
Or use this short link: https://bit.ly/3xVerifyNow
""")

# 8-a/b/c. Multiple related campaign emails --------------------------------
for i, (frm, subj, url) in enumerate([
    ("service@paypa1-verify.com", "Account limited - verify now",
     "http://paypa1-verify.com.secure-login.info/verify?acct=1"),
    ("support@paypa1-verify.com", "Final notice: account suspension",
     "http://paypa1-verify.com.secure-login.info/verify?acct=2"),
    ("noreply@paypa1-verify.com", "Immediate action required on your account",
     "http://paypa1-verify.com.secure-login.info/verify?acct=3"),
], start=1):
    write(f"campaign/campaign_{i:02d}.eml", f"""From: "PayPal Security" <{frm}>
To: victim{i}@example.com
Subject: {subj}
Date: Mon, 12 Oct 2026 0{i}:00:00 +0000
Message-ID: <camp{i:03d}@paypa1-verify.com>
Reply-To: recover@paypa1-verify.com
Return-Path: <bounce@paypa1-verify.com>
Received: from unknown (203.0.113.55) by mx.example.com; Mon, 12 Oct 2026 0{i}:00:00 +0000
Authentication-Results: mx.example.com; spf=fail; dkim=none; dmarc=fail
Content-Type: text/html; charset="utf-8"

<html><body><p>Please <a href="{url}">verify your account</a> now.</p></body></html>
""")

# 9. Malformed email -------------------------------------------------------
write("malformed/malformed_truncated.eml", """From: broken@example
To: someone
Subject
Date: not-a-date
This is not a properly formed header block
Content-Type: text/plain

Body text with no proper headers above it.
""")

write("malformed/malformed_empty.eml", "")

# 10. Attachment email ------------------------------------------------------
write("edge_cases/attachment_email.eml", """From: hr@company.com
To: employee@company.com
Subject: Your updated policy document
Date: Tue, 13 Oct 2026 09:00:00 +0000
Message-ID: <att001@company.com>
Received: from mail.company.com (192.0.2.5) by mx.company.com; Tue, 13 Oct 2026 08:59:50 +0000
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: multipart/mixed; boundary="BOUNDARY123"

--BOUNDARY123
Content-Type: text/plain; charset="utf-8"

Please find the attached policy document.

--BOUNDARY123
Content-Type: application/pdf; name="policy.pdf"
Content-Disposition: attachment; filename="policy.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcOkw7zDtsO4CjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURl
Y29kZT4+CnN0cmVhbQp4nDPQM1Qo5ypUMFAwALGMLXUtDBQ0DIA0lyGXi4KJgqGxqQVI3EDBSKGm
--BOUNDARY123--
""")

# Unicode / encoded headers -------------------------------------------------
write("edge_cases/unicode_encoded_headers.eml", """From: =?UTF-8?B?Sm9zw6kgUMOpcmV6?= <jose@example.com>
To: recipient@example.com
Subject: =?UTF-8?B?SG9sYSDCoSBUaWVuZXMgdW4gbWVuc2FqZSE=?=
Date: Wed, 14 Oct 2026 12:00:00 +0000
Message-ID: <unicode001@example.com>
Received: from mail.example.com (192.0.2.9) by mx.example.com; Wed, 14 Oct 2026 11:59:50 +0000
Authentication-Results: mx.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset="utf-8"

Hola, este es un mensaje de prueba con acentos: café, niño, corazón.
""")

# Multiple Received headers / multiple recipients ---------------------------
write("edge_cases/multi_received_multi_recipient.eml", """From: sender@example.com
To: alice@example.com, bob@example.com, carol@example.com
Cc: dave@example.com
Subject: Team update
Date: Thu, 15 Oct 2026 15:00:00 +0000
Message-ID: <multi001@example.com>
Received: from mx2.example.com (198.51.100.2) by mx1.example.com; Thu, 15 Oct 2026 14:59:55 +0000
Received: from relay.example.com (198.51.100.3) by mx2.example.com; Thu, 15 Oct 2026 14:59:50 +0000
Received: from origin.example.com (192.0.2.1) by relay.example.com; Thu, 15 Oct 2026 14:59:40 +0000
Authentication-Results: mx1.example.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset="utf-8"

Hi team, here's this week's update.
""")

print("Done generating synthetic test data.")
