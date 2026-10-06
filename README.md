# Phishing Email Analyser

An **educational, privacy-first** web app that helps you learn to spot the warning
signs of phishing and social-engineering emails. Paste an email, click **Analyse
Email**, and get an explainable 0-100 risk score with every warning sign described
in plain English.

Built with plain HTML, CSS and JavaScript. **No** server, database, accounts,
frameworks, dependencies or AI APIs.

---

## 1. Privacy: how it works and why you can trust it

- The analysis runs **entirely inside your web browser**. Nothing is uploaded,
  stored, logged or sent anywhere.
- There is **no backend server at all**, so there is nowhere for your email to go.
- The page includes a **Content-Security-Policy** that tells the browser to block
  all network requests from the page (`connect-src 'none'`). Your pasted text
  cannot be transmitted, even by accident.
- No tracking, no cookies, no analytics, no telemetry.

**Try it yourself:** open the page, then disconnect from the internet. The
analyser still works, because nothing ever leaves your device.

---

## 2. How to open the app

You do **not** need to install anything.

1. Open the folder `Cline AI`.
2. Double-click **`index.html`** (it opens in Edge, Chrome or any modern browser).
3. Paste an email (or click one of the fictional examples) and click **Analyse Email**.

> Tip: `Ctrl+Enter` (or `Cmd+Enter` on a Mac) also starts the analysis.

---

## 3. The fictional demonstration emails

All six examples are invented and use reserved, non-hostile addresses such as
`example.com` / `.example` and the documentation IP range `192.0.2.0/24`. They
contain **no real malicious domains and no working malicious links**.

| Button | What it teaches |
|---|---|
| Obvious phishing | Blatant threats, password/MFA requests, a raw-IP link |
| Sophisticated phishing | Subtle document-share lure with a look-alike domain |
| Fake Microsoft 365 | Account-closure threat plus credential-harvesting wording |
| Fake parcel delivery | Small "redelivery fee" scam |
| Fake invoice / BEC | Realistic business email compromise (bank-detail change) |
| Legitimate email | A genuine message that should score Low Risk |

---

## 4. How the score is calculated (nothing is hidden)

Each warning sign is a **rule** with a fixed number of points. When a rule finds
something, its points are added to a total, which is **capped at 100**.

| Severity | Typical points | Example |
|---|---|---|
| Informational | 2 | Generic greeting ("Dear Customer") |
| Low | 6-10 | Mild urgency or impersonation wording |
| Medium | 12-15 | Suspicious link, shortened URL, SPF/DKIM failure |
| High | 20-25 | Account-closure threat, bank-detail change, misleading link |
| Critical | 26-30 | Password request, MFA-code request, executable attachment |

**Risk bands:** `0-24` Low Risk · `25-59` Suspicious · `60-100` High Risk.

The results screen shows a **"How your score was calculated"** table listing every
rule that fired, its points and the exact text that triggered it, so you can learn
from each scan.

---

## 5. Warning signs it checks

**Language and content:** urgency and pressure; threats of account suspension or
closure; requests for passwords; requests for MFA / one-time codes; payment and
gift-card requests; requests to change bank details (BEC); impersonation of brands
or internal departments; unexpected invoice language; credential-harvesting
wording.

**Links:** suspicious domains (look-alike brands, punycode `xn--`, odd endings,
too many hyphens, brand used inside an unrelated domain); shortened URLs; URLs
using raw IP addresses; misleading link text (when email HTML is pasted).

**Attachments:** executable or dangerous file types and double extensions (for
example `invoice.pdf.exe`); risky archives and macro-enabled documents; requests
to enable macros or "content".

**Headers (only if you paste them):** `From` vs `Reply-To` mismatch; SPF failures;
DKIM failures; DMARC failures.

---

## 6. Testing the code

Open **`tests.html`** in your browser. It runs the real engine against the
examples and small inputs, and shows green/red results. At the time of writing it
reports **23 of 23 passing**.

---

## 7. Hosting it for free (optional)

Because it is a static site, you can publish it at no cost:

1. Put the files in a folder.
2. Upload them to a free static host such as **GitHub Pages**, **Cloudflare Pages**
   or **Netlify** (drag-and-drop is usually enough).
3. Visitors use it free, and all analysis still happens on their own device.

If your host serves the page from a plain web address, the Content-Security-Policy
continues to block outbound requests.

---

## 8. Customising it

- **Add or change a warning sign:** open `app.js`, find the `RULES` list near the
  middle of the file, and copy an existing rule. Change its `id`, `points`, `title`,
  `why`, `advice` and the `detector` word list. The score and interface update
  automatically.
- **Add an example email:** add a new entry to the `SAMPLES` object in `app.js`.
- **Change the colours or layout:** edit `styles.css`.

---

## 9. Important limitations and safety

- It **cannot** prove an email is malicious or safe. It is a **learning and triage
  aid**, not a replacement for your email provider's own security scanning.
- It only examines the **text and headers you paste**. It cannot see images, QR
  codes, hidden email internals, or where a link really leads.
- A high score means "many warning signs found", not "proven malicious". A low
  score means "no common warning signs found", not "proven safe".
- **Never** click links or open attachments to test them. Verify important
  messages using the organisation's official website or app (typed yourself), or a
  phone number you already know. Never use contact details supplied in an email.

---

## 10. Files in this project

```
index.html   The page and all its content
styles.css   The design (dark, responsive, no frameworks)
app.js       The analysis engine, rules, examples and interface logic
tests.html   Browser self-tests (open this to see them pass)
README.md    This guide
```
