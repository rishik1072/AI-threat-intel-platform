from __future__ import annotations

import random


def build_synthetic_training_corpus(seed: int = 42) -> dict:
    """
    Builds a small synthetic corpus so the platform is fully runnable offline.
    Replace with real labeled data for production use.

    Labels: 1 = phishing, 0 = safe
    """
    rnd = random.Random(seed)

    safe_urls = [
        "https://www.google.com",
        "https://github.com/login",
        "https://accounts.microsoft.com",
        "https://www.apple.com",
        "https://www.amazon.com",
        "https://paypal.com",
        "https://www.linkedin.com",
        "https://docs.python.org/3/",
        "https://en.wikipedia.org/wiki/Phishing",
        "https://www.reddit.com",
    ]

    phish_urls = [
        "http://secure-login-paypaI.com/verify",
        "http://account-update-microsoft.com/login",
        "https://xn--pple-43d.com/icloud/signin",
        "http://google.verify-session.com/security",
        "http://192.168.0.10/login",
        "http://paypal.com@evil.example/confirm",
        "https://login.github-security-alert.com/session",
        "http://secure.account.verify.update.example.com/signin",
        "http://amaz0n-support.example/reset-password",
        "http://dropbox-fileshare.example/verify",
    ]

    safe_emails = [
        "Hi team,\nCan we reschedule the meeting to Friday?\nThanks.",
        "Subject: Invoice\nPlease find the attached invoice for March.\nRegards, Finance",
        "Reminder: your package will arrive tomorrow between 10-12.",
        "Welcome! Your account has been created successfully.",
    ]

    phish_emails = [
        "Subject: Urgent action required\nYour account will be suspended within 24 hours. Verify your password immediately.",
        "Security alert: We noticed unusual activity. Please log in to confirm your identity.",
        "Dear customer, kindly update your payment details to avoid service interruption.",
        "Your one-time code is required. Sign in now to continue. This is urgent.",
    ]

    # Add some variations
    def jitter_url(u: str) -> str:
        if "?" in u:
            return u
        if rnd.random() < 0.4:
            return u + "?ref=" + str(rnd.randint(1000, 99999))
        if rnd.random() < 0.2:
            return u.replace("https://", "http://")
        return u

    url_samples = [(jitter_url(u), 0) for u in safe_urls] + [(jitter_url(u), 1) for u in phish_urls]
    rnd.shuffle(url_samples)

    text_samples_x = []
    text_samples_y = []

    # Train text model on both emails and URL strings (helps for URL keyword detection too)
    for t in safe_emails:
        text_samples_x.append(t)
        text_samples_y.append(0)
    for t in phish_emails:
        text_samples_x.append(t)
        text_samples_y.append(1)
    for u, y in url_samples:
        text_samples_x.append(u)
        text_samples_y.append(y)

    return {"url_samples": url_samples, "text_samples_x": text_samples_x, "text_samples_y": text_samples_y}

