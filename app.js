/* =============================================================================
   Phishing Email Analyser - analysis engine and user interface
   =============================================================================
   This whole file runs inside the visitor's web browser.

   IMPORTANT PRIVACY NOTE
   There is no network code in this file. It never sends, uploads, logs or
   stores the email that the user pastes. Every check below is a pure function
   that reads a string and returns a result, locally.

   HOW THE SCORE WORKS
   Each warning sign ("rule") has a fixed number of points. When a rule finds
   something, its points are added to the total. The total is capped at 100.
   Nothing is hidden: the interface lists every rule that fired, its points and
   the exact text that triggered it.
   ========================================================================== */

'use strict';

var SCORE_MAX = 100;
var BAND_HIGH = 60;        /* 60-100 = High Risk            */
var BAND_SUSPICIOUS = 25;  /* 25-59  = Suspicious           */
                           /* 0-24   = Low Risk             */

/* Brands commonly impersonated, and the domain they really belong to. */
var OFFICIAL = {
  microsoft: 'microsoft.com',
  'office 365': 'office.com',
  outlook: 'outlook.com',
  apple: 'apple.com',
  icloud: 'icloud.com',
  paypal: 'paypal.com',
  amazon: 'amazon.com',
  google: 'google.com',
  netflix: 'netflix.com',
  docusign: 'docusign.com',
  adobe: 'adobe.com',
  linkedin: 'linkedin.com',
  dropbox: 'dropbox.com',
  dhl: 'dhl.com',
  fedex: 'fedex.com',
  ups: 'ups.com',
  usps: 'usps.com'
};

/* Domain endings frequently used by short-lived phishing sites. */
var SUSPICIOUS_TLDS = ['zip', 'mov', 'top', 'xyz', 'tk', 'gq', 'ml', 'cf', 'ga',
  'work', 'click', 'country', 'stream', 'download', 'review', 'loan', 'date',
  'racing', 'win', 'bid', 'science', 'party', 'gdn', 'men', 'cam', 'rest',
  'buzz', 'surf', 'monster', 'quest', 'cyou', 'sbs', 'lol', 'icu', 'wang'];

/* Well-known link shorteners: they hide the real destination. */
var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'rebrand.ly', 'cutt.ly', 'shorturl.at', 'rb.gy', 'bit.do',
  'tiny.cc', 't.ly', 'surl.li', 'clck.ru', 'v.gd', 'bl.ink', 'u.to', 'qps.ru'];

/* File types that can run code or install software. */
var EXEC_EXTS = ['exe', 'scr', 'js', 'jse', 'vbs', 'vbe', 'wsf', 'wsh', 'bat',
  'cmd', 'pif', 'jar', 'msi', 'msp', 'ps1', 'cpl', 'hta', 'lnk', 'reg', 'iso',
  'img', 'vhd', 'ace', 'apk', 'dll', 'gadget', 'msc'];

/* Archive and other risky document types. */
var RISKY_EXTS = ['zip', 'rar', '7z', 'gz', 'tar', 'cab', 'htm', 'html',
  'docm', 'xlsm', 'pptm', 'dotm', 'xltm'];

/* Look-alike brand names made with digits or similar-looking letters. */
var LOOKALIKE = /(micr0soft|m1crosoft|micros0ft|rnicrosoft|paypa1|paypai|g00gle|goog1e|amaz0n|amazan|app1e|netfl1x|faceb00k|docus1gn|0ffice|1cloud)/i;

/* -----------------------------------------------------------------------------
   Small helper functions
   -------------------------------------------------------------------------- */

function normalizeText(s) {
  return String(s === undefined || s === null ? '' : s).replace(/\r\n?/g, '\n');
}

function dedupe(list) {
  var seen = {};
  var out = [];
  for (var i = 0; i < list.length; i++) {
    var key = String(list[i]).toLowerCase();
    if (!seen[key]) { seen[key] = true; out.push(list[i]); }
  }
  return out;
}

function clip(s, max) {
  var t = String(s).replace(/\s+/g, ' ').trim();
  return t.length > max ? t.slice(0, max - 1) + '\u2026' : t;
}

/* Turn a plain phrase into a case-insensitive regular expression. */
function phraseRegex(phrase) {
  var escaped = String(phrase).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  escaped = escaped.replace(/\s+/g, '\\s+');
  return new RegExp(escaped, 'gi');
}

/* Collect every match for a list of phrases / regular expressions. */
function collect(text, phrases) {
  var out = [];
  if (!text) { return out; }
  for (var i = 0; i < phrases.length; i++) {
    var p = phrases[i];
    var re = (p instanceof RegExp) ? p : phraseRegex(p);
    re.lastIndex = 0;
    var m = text.match(re);
    if (m) {
      for (var j = 0; j < m.length; j++) { out.push(clip(m[j], 90)); }
    }
  }
  return dedupe(out);
}

/* -----------------------------------------------------------------------------
   Parsing: headers, addresses, URLs and HTML links
   -------------------------------------------------------------------------- */

/* Split pasted text into (optional) header block and body. */
function parseHeaders(text) {
  var lines = normalizeText(text).split('\n');
  var headers = [];
  var i = 0;
  var started = false;

  for (; i < lines.length; i++) {
    var line = lines[i];
    if (line.trim() === '') {
      if (started) { break; }
      continue; /* allow leading blank lines */
    }
    var m = line.match(/^([A-Za-z][A-Za-z0-9-]*):\s?(.*)$/);
    if (m) {
      headers.push({ name: m[1].toLowerCase(), value: m[2] });
      started = true;
    } else if (started && /^\s+\S/.test(line)) {
      /* folded (continued) header line */
      headers[headers.length - 1].value += ' ' + line.trim();
    } else {
      break; /* first real body line */
    }
  }

  return { headers: headers, body: lines.slice(i).join('\n') };
}

function getHeader(headers, name) {
  for (var i = 0; i < headers.length; i++) {
    if (headers[i].name === name) { return headers[i].value; }
  }
  return '';
}

function headerTextOf(headers) {
  var out = [];
  for (var i = 0; i < headers.length; i++) {
    out.push(headers[i].name + ': ' + headers[i].value);
  }
  return out.join('\n');
}

function addressDomain(value) {
  var m = String(value || '').match(/[A-Za-z0-9._%+-]+@([A-Za-z0-9.-]+)/);
  if (!m) { return ''; }
  return m[1].toLowerCase().replace(/[>.,;)\]]+$/, '');
}

function displayNameOf(value) {
  var v = String(value || '');
  var m = v.match(/^\s*"?([^"<]*?)"?\s*</);
  if (m && m[1].trim()) { return m[1].trim(); }
  return '';
}

/* The "registered" part of a domain (e.g. a.b.example.co.uk -> example.co.uk). */
function registrableDomain(host) {
  var labels = String(host || '').toLowerCase().split('.').filter(function (x) { return x; });
  if (labels.length <= 2) { return labels.join('.'); }
  var twoPart = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'com.au', 'co.nz', 'com.br', 'co.in', 'com.mx'];
  var last2 = labels.slice(-2).join('.');
  if (twoPart.indexOf(last2) !== -1) { return labels.slice(-3).join('.'); }
  return last2;
}

function extractUrls(text) {
  var found = [];
  var re = /\b(?:https?:\/\/|www\.)[^\s<>"'\\)\]}]+/gi;
  var m;
  while ((m = re.exec(text)) !== null) {
    found.push(m[0].replace(/[.,;:!?]+$/, ''));
  }
  return dedupe(found);
}

function hostFromUrl(url) {
  var s = String(url || '');
  var withProto = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : 'http://' + s;
  try {
    return new URL(withProto).hostname.toLowerCase();
  } catch (e) {
    var m = s.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?(?:[^@/]+@)?([^/:?#]+)/i);
    return m ? m[1].toLowerCase() : '';
  }
}

function isIpv4(host) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(String(host || ''));
}

function extractAnchors(text) {
  var anchors = [];
  var re = /<a\b[^>]*href\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>([\s\S]*?)<\/a>/gi;
  var m;
  while ((m = re.exec(text)) !== null) {
    var href = m[1] || m[2] || m[3] || '';
    var label = m[4].replace(/<[^>]*>/g, '').replace(/\s+/g, ' ').trim();
    anchors.push({ href: href, text: label });
  }
  return anchors;
}

/* Find which impersonated brand (if any) appears inside a host name. */
function brandInHost(host) {
  var h = String(host || '').toLowerCase();
  for (var brand in OFFICIAL) {
    if (Object.prototype.hasOwnProperty.call(OFFICIAL, brand) && h.indexOf(brand) !== -1) {
      return brand;
    }
  }
  return '';
}

function brandInText(text) {
  var t = String(text || '').toLowerCase();
  for (var brand in OFFICIAL) {
    if (Object.prototype.hasOwnProperty.call(OFFICIAL, brand) && t.indexOf(brand) !== -1) {
      return brand;
    }
  }
  return '';
}

/* -----------------------------------------------------------------------------
   Analysis helpers for links and attachments
   -------------------------------------------------------------------------- */

/* Returns human-readable reasons for any web address that looks suspicious. */
function suspiciousUrlEvidence(urls) {
  var out = [];
  for (var i = 0; i < urls.length; i++) {
    var raw = urls[i];
    var host = hostFromUrl(raw);
    if (!host || isIpv4(host)) { continue; } /* bare IPs are handled by their own rule */

    var reasons = [];
    if (host.indexOf('xn--') !== -1) {
      reasons.push('punycode name (xn--) that can imitate another domain');
    }
    if (raw.indexOf('@') !== -1) {
      reasons.push('contains an "@" that can hide the real destination');
    }
    var tld = host.split('.').pop();
    if (SUSPICIOUS_TLDS.indexOf(tld) !== -1) {
      reasons.push('unusual domain ending ".' + tld + '"');
    }
    if (LOOKALIKE.test(host)) {
      reasons.push('brand name written with look-alike characters');
    }
    if ((host.match(/-/g) || []).length >= 3) {
      reasons.push('an unusually high number of hyphens');
    }
    var brand = brandInHost(host);
    if (brand && registrableDomain(host) !== OFFICIAL[brand]) {
      reasons.push('mentions "' + brand + '" but the real domain is "' + registrableDomain(host) + '"');
    }
    if (!brand && host.split('.').length >= 4) {
      reasons.push('an unusually long list of sub-domains');
    }
    if (!brand && /(^|[.-])(login|secure|verify|account|signin|update|billing|support)[.-]/.test(host)) {
      reasons.push('sensitive words such as "login" or "secure" inside the address');
    }

    if (reasons.length) { out.push(raw + '  \u2192  ' + reasons.join('; ')); }
  }
  return dedupe(out);
}

/* Compares the visible text of an HTML link with where it actually points. */
function misleadingAnchorEvidence(anchors) {
  var out = [];
  for (var i = 0; i < anchors.length; i++) {
    var a = anchors[i];
    var hrefHost = hostFromUrl(a.href);
    if (!hrefHost) { continue; }
    var textDomains = a.text.match(/\b([a-z0-9-]+\.)+[a-z]{2,}\b/gi) || [];
    for (var j = 0; j < textDomains.length; j++) {
      var shown = textDomains[j].toLowerCase();
      if (registrableDomain(shown) !== registrableDomain(hrefHost)) {
        out.push('link text shows "' + shown + '" but the link really points to "' + hrefHost + '"');
      }
    }
  }
  return dedupe(out);
}

/* Reads the SPF / DKIM / DMARC result out of pasted authentication headers. */
function authEvidence(headerText, which) {
  var t = String(headerText || '');
  if (!t) { return []; }
  var reasons = [];
  var statusRe = new RegExp('\\b' + which + '\\s*=\\s*([a-z]+)\\b', 'gi');
  var m;
  while ((m = statusRe.exec(t)) !== null) {
    var status = m[1].toLowerCase();
    if (status === 'fail' || status === 'hardfail' || status === 'softfail' || status === 'permerror') {
      reasons.push(which.toUpperCase() + ' result: ' + status);
    }
  }
  if (which === 'spf') {
    var lines = t.match(/received-spf:[^\n]*/gi) || [];
    for (var i = 0; i < lines.length; i++) {
      if (/\b(fail|softfail|permerror)\b/i.test(lines[i])) { reasons.push(clip(lines[i], 110)); }
    }
  }
  return dedupe(reasons);
}

/* Finds dangerous file names, including trick double extensions. */
function executableEvidence(text) {
  var out = [];
  var ext = EXEC_EXTS.join('|');
  var re1 = new RegExp('\\b[\\w.\\-]+\\.(' + ext + ')\\b', 'gi');
  var m;
  while ((m = re1.exec(text)) !== null) { out.push(m[0]); }
  var re2 = new RegExp('\\b[\\w.\\-]+\\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|rtf|zip|html?)\\.(' + ext + ')\\b', 'gi');
  while ((m = re2.exec(text)) !== null) { out.push(m[0] + '  (double extension)'); }
  return dedupe(out);
}

/* Finds risky (but not directly executable) attachment types. */
function unusualAttachmentEvidence(text) {
  var out = [];
  var ext = RISKY_EXTS.join('|');
  var re = new RegExp('\\b[\\w.\\-]+\\.(' + ext + ')\\b', 'gi');
  var m;
  while ((m = re.exec(text)) !== null) { out.push(m[0]); }
  if (/(password[- ]?(protected|required))[^.\n]{0,40}(zip|archive|attachment|file)/i.test(text)) {
    out.push('a password-protected archive is mentioned');
  }
  if (/(password|pwd)\s*(for|is|:)\s*the\s*(attachment|file|archive|zip)/i.test(text)) {
    out.push('a password is supplied for a protected archive');
  }
  return dedupe(out);
}

/* -----------------------------------------------------------------------------
   THE RULES - every warning sign the analyser looks for.
   Each rule has a fixed number of points, a plain-English reason ("why") and
   practical advice. This is what makes the risk score explainable.
   -------------------------------------------------------------------------- */

var RULES = [

  {
    id: 'generic_greeting',
    category: 'Content',
    severity: 'info',
    points: 2,
    title: 'Generic greeting instead of your name',
    why: 'Organisations you really deal with normally address you by name. A vague greeting such as "Dear Customer" is typical of bulk phishing sent to thousands of people at once.',
    advice: 'Treat a generic greeting as a weak signal, not proof. Check the sender address carefully.',
    detector: function (c) {
      return collect(c.body, ['dear customer', 'dear user', 'dear sir/madam', 'dear sir or madam',
        'dear madam or sir', 'valued customer', 'dear account holder', 'dear client', 'dear member',
        'dear email user', 'dear account user']);
    }
  },

  {
    id: 'urgency',
    category: 'Urgency & Pressure',
    severity: 'medium',
    points: 8,
    title: 'Urgency or pressure language',
    why: 'Phishing relies on rushing you so that you act before you think. Phrases that create a deadline or a sense of emergency are classic social-engineering tactics.',
    advice: 'Slow down. Genuine organisations rarely demand instant action by email. Verify the message through a channel you already trust.',
    detector: function (c) {
      return collect(c.body, ['urgent', 'urgently', 'immediately', 'as soon as possible', 'act now',
        'right away', 'within 24 hours', 'within 48 hours', 'within 2 hours', 'within the next 24 hours',
        'final notice', 'last warning', 'final warning', 'time sensitive', 'time-sensitive',
        "don't delay", 'do not delay', 'act fast', 'respond promptly', 'limited time',
        'failure to respond', 'without delay', 'expires today', 'expiring soon', 'last chance',
        'immediate action', 'urgent action']);
    }
  },

  {
    id: 'account_threat',
    category: 'Account Threats',
    severity: 'high',
    points: 20,
    title: 'Threat that your account will be suspended, closed or restricted',
    why: 'Threatening to close, suspend, lock or delete an account is a scare tactic designed to make you act quickly. Legitimate providers rarely threaten immediate closure by email.',
    advice: "Do not act through the email. Open the provider's official app or website yourself and check your account status there.",
    detector: function (c) {
      return collect(c.body, ['account will be suspended', 'account has been suspended',
        'your account will be closed', 'account will be terminated', 'will be deactivated',
        'will be locked', 'permanently disabled', 'permanently closed', 'access will be revoked',
        'legal action', 'will be deleted', 'suspension of your account',
        'your account will be restricted', 'account has been locked', 'account suspended',
        'unusual sign-in', 'unusual activity', 'suspicious activity', 'unauthorized access',
        'unauthorised access', 'we have detected', 'your account is at risk']);
    }
  },

  {
    id: 'password_request',
    category: 'Credential Requests',
    severity: 'critical',
    points: 30,
    title: 'Request for your password or login credentials',
    why: 'No legitimate organisation will ever ask you to send, confirm or enter your password in an email. This is one of the strongest signs of credential harvesting.',
    advice: 'Never reply with your password and never type it into a page reached from an email link. If you already did, change that password immediately and turn on two-factor authentication.',
    detector: function (c) {
      return collect(c.body, [
        /(enter|provide|confirm|verify|send|reply with|share|submit|update|reset|type|re-?enter)[^.\n]{0,40}\b(password|passphrase|login credentials|your credentials|username and password)\b/i,
        /\bpassword\b[^.\n]{0,30}\b(will expire|expires|has expired|needs to be (reset|updated|changed))\b/i
      ]);
    }
  },

  {
    id: 'mfa_request',
    category: 'Credential Requests',
    severity: 'critical',
    points: 30,
    title: 'Request for a verification or one-time code (MFA / OTP)',
    why: 'A one-time code is the key to your account. If someone asks you to send or type it, they are almost certainly trying to steal access to your account \u2014 even if the code itself is genuine.',
    advice: 'Never share a one-time code with anyone. If you received a code you did not request, someone may already have your password \u2014 change it now and turn on two-factor authentication.',
    detector: function (c) {
      return collect(c.body, [
        /\b(verification|security|authentication|confirmation|access)\s+code\b/i,
        /\bone[- ]?time\s+(code|password|pin|passcode)\b/i,
        /\b(otp|2fa|two[- ]?factor|multi[- ]?factor)\b/i,
        /\b(six|6)[- ]?digit\s+code\b/i,
        /\bcode\s+(we|i)\s+(just\s+)?(sent|texted|emailed|generated)\b/i,
        /\bauthenticator\s+code\b/i,
        /\bcode\s+to\s+(verify|confirm)\b/i
      ]);
    }
  },

  {
    id: 'payment_request',
    category: 'Payment Requests',
    severity: 'high',
    points: 22,
    title: 'Payment, gift-card or cryptocurrency request',
    why: 'Gift cards, cryptocurrency and unusual transfers are hard to trace and are a favourite of scammers. Genuine organisations do not ask for payment in gift cards or crypto.',
    advice: 'Never pay with gift cards, crypto, or an unusual method requested by email. Verify any payment request by phone using a number you already know.',
    detector: function (c) {
      return collect(c.body, ['gift card', 'gift cards', 'itunes card', 'google play card', 'steam card',
        'amazon card', 'prepaid card', 'apple card', 'wire transfer', 'bank transfer', 'bitcoin',
        'cryptocurrency', 'crypto wallet', 'money transfer', 'western union', 'moneygram',
        'purchase the card', 'load the card', 'pay now', 'processing fee', 'redelivery fee',
        'small fee', 'payment required', 'payment of', 'pay a fee']);
    }
  },

  {
    id: 'bank_change',
    category: 'Banking Changes',
    severity: 'high',
    points: 25,
    title: 'Request to change bank or payment details',
    why: 'A sudden request to change bank account or payment details is the classic "business email compromise" (BEC) fraud, in which payments are redirected to a fraudster.',
    advice: 'Always confirm a change of bank details by speaking to a known contact on a number you already have \u2014 never using details supplied in the email.',
    detector: function (c) {
      return collect(c.body, ['new bank details', 'changed bank details', 'update our bank details',
        'update your bank details', 'change the bank details', 'new bank account', 'new account number',
        'new routing number', 'new sort code', 'update payment information', 'update payment details',
        'payment details have changed', 'banking details have changed', 'change of bank account',
        'direct deposit', 'our account has changed', 'new account details']);
    }
  },

  {
    id: 'impersonation',
    category: 'Impersonation',
    severity: 'medium',
    points: 10,
    title: 'Language that impersonates a trusted organisation or department',
    why: 'Phishing emails often pose as a well-known brand, or as an internal department (IT, helpdesk, security team), in order to borrow that trust.',
    advice: 'Check the sender\'s full email address, not just the display name. A famous name in the "from" label proves nothing.',
    detector: function (c) {
      return collect(c.text, ['microsoft account team', 'microsoft 365', 'office 365', 'apple id',
        'apple support', 'paypal security', 'amazon security', 'google security', 'it department',
        'it support', 'it helpdesk', 'helpdesk', 'help desk', 'security team', 'system administrator',
        'technical support', 'account team', 'customer support team', 'fraud department',
        'our security department', 'it service desk']);
    }
  },

  {
    id: 'invoice_language',
    category: 'Content',
    severity: 'medium',
    points: 12,
    title: 'Unexpected invoice or payment-demand language',
    why: 'A surprise invoice, overdue notice or final demand is a common lure: it encourages you to open an attachment or click a link quickly.',
    advice: 'Do not open the attachment. If you were not expecting an invoice from this sender, verify it using the company\'s official contact details.',
    detector: function (c) {
      return collect(c.body, ['invoice attached', 'attached invoice', 'please find the invoice',
        'please see attached invoice', 'invoice is attached', 'past due', 'overdue payment',
        'payment is overdue', 'outstanding balance', 'remittance', 'purchase order', 'unpaid invoice',
        'invoice number', 'final demand', 'payment reminder', 'overdue invoice',
        'outstanding invoice', 'payment is due', 'due invoice']);
    }
  },

  {
    id: 'credential_harvesting',
    category: 'Credential Requests',
    severity: 'high',
    points: 20,
    title: 'Credential-harvesting / "verify your account" language',
    why: 'Phrases such as "verify your account" or "confirm your identity" are used to funnel you to a fake login page that steals your details.',
    advice: 'Do not use any login link in the email. Go to the official website or app directly and log in from there.',
    detector: function (c) {
      return collect(c.body, ['verify your account', 'confirm your account', 'verify your identity',
        'confirm your identity', 're-enter your', 'update your credentials', 'validate your account',
        'confirm your details', 'unlock your account', 'restore your account',
        'verify your information', 'confirm your information', 'click below to verify',
        'sign in to verify', 'login to verify', 'reactivate your account', 'confirm your sign-in',
        'verify your email', 'confirm your email address', 'secure your account', 'sign-in attempt']);
    }
  },

  {
    id: 'macro_request',
    category: 'Attachments',
    severity: 'high',
    points: 22,
    title: 'Instruction to enable macros or editing',
    why: 'Enabling macros or "content" allows a document to run code on your computer, which is a well-known way to deliver malware.',
    advice: 'Never enable macros or content in a document you were not expecting, even if the message insists it is necessary.',
    detector: function (c) {
      return collect(c.text, ['enable macros', 'enable macro', 'enable editing', 'enable content',
        'enable the content', 'click enable content', 'enable "edit"', 'allow macros',
        'macros must be enabled', 'if the document is protected', 'protected view']);
    }
  },

  {
    id: 'shortened_url',
    category: 'Links & URLs',
    severity: 'medium',
    points: 12,
    title: 'Shortened link that hides its real destination',
    why: 'Shortened links hide the real web address, so you cannot see where a link actually leads before clicking it.',
    advice: 'Do not click shortened links. If you must check one, use a link-expander service you trust \u2014 or simply go to the organisation\'s official website instead.',
    detector: function (c) {
      var out = [];
      for (var i = 0; i < c.urls.length; i++) {
        var host = hostFromUrl(c.urls[i]);
        if (SHORTENERS.indexOf(host) !== -1 || SHORTENERS.indexOf(registrableDomain(host)) !== -1) {
          out.push(c.urls[i]);
        }
      }
      return dedupe(out);
    }
  },

  {
    id: 'raw_ip_url',
    category: 'Links & URLs',
    severity: 'high',
    points: 22,
    title: 'Link uses a raw IP address instead of a domain name',
    why: 'Real services use readable domain names. A link to a bare numerical IP address is unusual and is often used to avoid being blocked or traced.',
    advice: 'Do not visit bare-IP links. Legitimate organisations publish their services on named domains.',
    detector: function (c) {
      var out = [];
      for (var i = 0; i < c.urls.length; i++) {
        if (isIpv4(hostFromUrl(c.urls[i]))) { out.push(c.urls[i]); }
      }
      return dedupe(out);
    }
  },

  {
    id: 'suspicious_url',
    category: 'Links & URLs',
    severity: 'medium',
    points: 14,
    title: 'Suspicious web address',
    why: 'Certain addresses are typical of phishing: misspelled or look-alike brand names, unusual domain endings, punycode (xn--) names, many hyphens, or a trusted brand used as a sub-domain of an unrelated site.',
    advice: 'Do not click. Type the organisation\'s official address yourself, or use its official app.',
    detector: function (c) {
      return suspiciousUrlEvidence(c.urls);
    }
  },

  {
    id: 'misleading_link_text',
    category: 'Links & URLs',
    severity: 'high',
    points: 20,
    title: 'Link text does not match where the link really goes',
    why: 'Attackers show a trusted address as the clickable text while the actual link points somewhere else. This is only detectable when the original HTML of the email is available.',
    advice: 'Treat any trusted-looking link text as untrustworthy. Navigate to the official site yourself rather than clicking.',
    detector: function (c) {
      return misleadingAnchorEvidence(c.anchors);
    }
  },

  {
    id: 'sender_spoof',
    category: 'Impersonation',
    severity: 'high',
    points: 15,
    title: 'Sender display name appears to impersonate a brand',
    why: 'The friendly "from" name is easy to fake. Seeing a trusted brand in the display name while the actual email address is unrelated is a strong warning sign.',
    advice: 'Always trust the full email address, not the display name.',
    detector: function (c) {
      if (!c.fromDisplay || !c.from) { return []; }
      var brand = brandInText(c.fromDisplay);
      if (brand && registrableDomain(c.fromDomain) !== OFFICIAL[brand]) {
        return ['sender name is "' + c.fromDisplay + '" but the address is ' + c.from];
      }
      return [];
    }
  },

  {
    id: 'replyto_mismatch',
    category: 'Email Authentication',
    severity: 'high',
    points: 20,
    title: '"Reply-To" address differs from the sender',
    why: 'When replies would go to a different domain than the one that sent the message, your reply can be diverted to an attacker. This is often used in business email compromise.',
    advice: 'Compare the From and Reply-To addresses. If they differ unexpectedly, treat the message as suspicious.',
    detector: function (c) {
      if (!c.fromDomain || !c.replyToDomain) { return []; }
      if (registrableDomain(c.fromDomain) !== registrableDomain(c.replyToDomain)) {
        return ['From: ' + c.from + '  |  Reply-To: ' + c.replyTo];
      }
      return [];
    }
  },

  {
    id: 'spf_fail',
    category: 'Email Authentication',
    severity: 'medium',
    points: 15,
    title: 'SPF authentication failed',
    why: 'SPF lets a domain list which servers may send its mail. A "fail" means the message came from a server that the domain does not authorise.',
    advice: 'An SPF failure is strong evidence of possible spoofing. Check the other warning signs too, because forwarding can occasionally cause failures.',
    detector: function (c) { return authEvidence(c.headerText, 'spf'); }
  },

  {
    id: 'dkim_fail',
    category: 'Email Authentication',
    severity: 'medium',
    points: 12,
    title: 'DKIM authentication failed',
    why: 'DKIM is a cryptographic signature that proves a message was not altered in transit. A "fail" means the signature did not verify, which can indicate tampering or a forged sender.',
    advice: 'Treat a DKIM failure as a supporting warning sign, and weigh it with the other findings.',
    detector: function (c) { return authEvidence(c.headerText, 'dkim'); }
  },

  {
    id: 'dmarc_fail',
    category: 'Email Authentication',
    severity: 'high',
    points: 20,
    title: 'DMARC authentication failed',
    why: 'DMARC ties SPF and DKIM together with the domain\'s own policy. A "fail" means the message did not pass the sender domain\'s authentication rules.',
    advice: 'A DMARC failure is a serious authentication warning. Do not act on the message until you have verified it independently.',
    detector: function (c) { return authEvidence(c.headerText, 'dmarc'); }
  },

  {
    id: 'executable_attachment',
    category: 'Attachments',
    severity: 'critical',
    points: 26,
    title: 'Executable or dangerous attachment type',
    why: 'Files that can run code (programs, scripts, shortcut files and disk images) are used to install malware. A double extension such as "invoice.pdf.exe" is designed to fool you into thinking it is a harmless document.',
    advice: 'Do not open or run the attachment. Delete the message, or report it to your IT / security team.',
    detector: function (c) { return executableEvidence(c.text); }
  },

  {
    id: 'unusual_attachment',
    category: 'Attachments',
    severity: 'medium',
    points: 12,
    title: 'Unusual or risky attachment',
    why: 'Archives, HTML files and macro-enabled Office documents are often used to deliver malware because they can run code or hide a second file inside.',
    advice: 'Only open attachments you are expecting, from a sender you can verify.',
    detector: function (c) { return unusualAttachmentEvidence(c.text); }
  }

];

/* -----------------------------------------------------------------------------
   The analysis engine: run every rule and build an explainable result
   -------------------------------------------------------------------------- */

var BAND_INFO = {
  low: {
    label: 'Low Risk',
    verdict: 'No common phishing warning signs were detected in this message. That does not prove it is safe \u2014 stay cautious with unexpected requests.'
  },
  suspicious: {
    label: 'Suspicious',
    verdict: 'This message shows several warning signs of phishing or social engineering. Treat it with caution and verify it independently before acting.'
  },
  high: {
    label: 'High Risk',
    verdict: 'This message shows strong warning signs of phishing or social engineering. Do not interact with it; verify it through an official channel instead.'
  }
};

function analyzeEmail(raw) {
  var text = normalizeText(raw);
  var parsed = parseHeaders(text);
  var headers = parsed.headers;
  var from = getHeader(headers, 'from');
  var replyTo = getHeader(headers, 'reply-to');

  var ctx = {
    raw: text,
    text: text,
    body: parsed.body,
    headers: headers,
    headerText: headerTextOf(headers),
    urls: extractUrls(text),
    anchors: extractAnchors(text),
    from: from,
    fromDomain: addressDomain(from),
    fromDisplay: displayNameOf(from),
    replyTo: replyTo,
    replyToDomain: addressDomain(replyTo)
  };

  var findings = [];
  for (var i = 0; i < RULES.length; i++) {
    var rule = RULES[i];
    var evidence;
    try {
      evidence = rule.detector(ctx) || [];
    } catch (err) {
      evidence = [];
    }
    evidence = dedupe(evidence).filter(function (x) { return Boolean(x); });
    if (evidence.length) {
      findings.push({
        id: rule.id,
        category: rule.category,
        severity: rule.severity,
        points: rule.points,
        title: rule.title,
        why: rule.why,
        advice: rule.advice,
        evidence: evidence
      });
    }
  }

  /* Most serious findings first. */
  findings.sort(function (a, b) { return b.points - a.points; });

  var rawTotal = 0;
  for (var j = 0; j < findings.length; j++) { rawTotal += findings[j].points; }
  var score = Math.min(SCORE_MAX, rawTotal);
  var band = score >= BAND_HIGH ? 'high' : (score >= BAND_SUSPICIOUS ? 'suspicious' : 'low');

  return {
    score: score,
    rawTotal: rawTotal,
    capped: rawTotal > SCORE_MAX,
    band: band,
    findings: findings,
    meta: {
      length: text.length,
      urlCount: ctx.urls.length,
      headerCount: headers.length,
      from: from,
      replyTo: replyTo
    }
  };
}

/* -----------------------------------------------------------------------------
   Build the "what you should do next" advice from the findings
   -------------------------------------------------------------------------- */

function buildRecommendations(result) {
  var cats = {};
  for (var i = 0; i < result.findings.length; i++) {
    cats[result.findings[i].category] = true;
  }
  var recs = [];

  if (result.findings.length === 0) {
    recs.push('No common warning signs were found. That is not a guarantee the message is safe, so stay cautious \u2014 especially with unexpected requests for money, information or action.');
  }
  if (cats['Links & URLs']) {
    recs.push('Do not click any links in this message. If you need to reach the organisation, type its official web address yourself or use its official app.');
  }
  if (cats['Attachments']) {
    recs.push('Do not open the attachment. If you already opened it, disconnect from the internet, run a full antivirus scan and ask your IT team for help.');
  }
  if (cats['Credential Requests']) {
    recs.push('Never send your password or a one-time code by email, and never type them into a page reached from an email link.');
    recs.push('If you already entered your password or a code, change that password now, turn on two-factor authentication and tell your IT team.');
  }
  if (cats['Payment Requests'] || cats['Banking Changes']) {
    recs.push('Do not send money or change bank details based on this email. Confirm with a known contact using a phone number you already have.');
    recs.push('If you may have sent money or shared account details, contact your bank immediately using the number on your card or statement.');
  }
  if (cats['Email Authentication']) {
    recs.push('An authentication failure (SPF / DKIM / DMARC) suggests the sender may be spoofed. Verify the message through an official channel before trusting it.');
  }

  recs.push('Verify independently: use the organisation\'s official website or app, or call a number you already know \u2014 never contact details supplied in the email.');
  recs.push('Report the message (for example, your email provider\'s "Report phishing" option, or your IT / security team), then delete it.');
  return recs;
}

/* -----------------------------------------------------------------------------
   FICTIONAL demonstration emails
   These are invented for learning. They contain NO real malicious domains and
   NO working malicious links. Reserved example domains (example.com, .example,
   .invalid) and the reserved test IP range 192.0.2.0/24 are used on purpose.
   -------------------------------------------------------------------------- */

var SAMPLES = {};

SAMPLES.obvious = [
  'From: "Microsoft Account Team" <security@microsoft-support.example>',
  'Reply-To: recovery@mail-verify.example',
  'Subject: URGENT: your account will be suspended in 24 hours!',
  '',
  'Dear Customer,',
  '',
  'We have detected unusual activity on your Microsoft 365 account. Your account will be',
  'suspended within 24 hours unless you verify your account immediately.',
  '',
  'To keep your account, click here to verify your password and confirm your identity:',
  'http://192.0.2.10/login/verify.php',
  '',
  'You must also send us the 6-digit verification code we sent to your phone.',
  '',
  'Failure to respond will result in your account being permanently closed and legal action.',
  '',
  'Microsoft Account Team'
].join('\n');

SAMPLES.sophisticated = [
  'From: "Aisha Rahman" <aisha.rahman@docusign-secure.example>',
  'Reply-To: aisha.rahman@docusign-secure.example',
  'Subject: Please review: Q3 supplier agreement',
  '',
  'Hello,',
  '',
  'I have shared the Q3 supplier agreement with you for review. Please find the invoice',
  'attached and sign at your earliest convenience.',
  '',
  'View document: https://docusign-secure.example/view/9f3a2b1c',
  '',
  'Attachment: Supplier_Agreement_Q3.pdf.htm',
  '',
  'Kind regards,',
  'Aisha Rahman',
  'Procurement'
].join('\n');

SAMPLES.microsoft365 = [
  'From: Microsoft 365 <no-reply@office365-notifications.example>',
  'Subject: Action required: unusual sign-in activity',
  '',
  'Dear User,',
  '',
  'We blocked a sign-in to your Office 365 account from an unrecognised device.',
  '',
  'To restore access, please confirm your identity and update your credentials:',
  'https://office365-notifications.example/identity/confirm',
  '',
  'Sign in to verify your information. If you do not do this within 24 hours we will',
  'lock your account and your account will be suspended.',
  '',
  'Microsoft 365 Security'
].join('\n');

SAMPLES.parcel = [
  'From: "DHL Express Delivery" <tracking@dhl-parcel-tracking.example>',
  'Subject: Your parcel could not be delivered',
  '',
  'Dear Customer,',
  '',
  'We attempted to deliver your parcel today but nobody was available. A small redelivery',
  'fee of 1.99 is required before we can try again.',
  '',
  'Please pay now to reschedule delivery: http://example.org/pay/parcel',
  '',
  'If the fee is not paid within 48 hours your parcel will be returned to sender.',
  '',
  'DHL Delivery Team'
].join('\n');

SAMPLES.bec = [
  'From: "Robert Chen, CFO" <r.chen@example-corp-finance.example>',
  'Reply-To: finance.dept@secure-payments.example',
  'Subject: Updated bank details for invoice #INV-2291',
  '',
  'Hi,',
  '',
  'Please update our bank details on file before paying the attached invoice for the Q3',
  'supplier work. Our account has changed and the new bank details are below.',
  '',
  'The new bank details are attached:',
  'New bank account: 00000000',
  'New sort code: 00-00-00',
  '',
  'Kindly process the payment today and confirm. This is urgent.',
  '',
  'Thanks,',
  'Robert Chen',
  'Chief Financial Officer'
].join('\n');

SAMPLES.legit = [
  'From: Priya Nair <priya.nair@example.com>',
  'Reply-To: priya.nair@example.com',
  'Subject: Notes from Thursday\'s awareness session',
  '',
  'Hi Sam,',
  '',
  'Thanks for joining the awareness session on Thursday. As promised, here are my notes',
  'from the discussion.',
  '',
  'We covered:',
  '- how to recognise suspicious messages',
  '- why you should check unexpected requests using a known contact',
  '- where to report anything unusual to the service desk',
  '',
  'No action is needed from you. If you would like to book a follow-up session, just',
  'reply to this email.',
  '',
  'Best wishes,',
  'Priya',
  'Priya Nair',
  'Awareness Lead, Example Corp'
].join('\n');

/* -----------------------------------------------------------------------------
   USER INTERFACE
   All rendering uses safe DOM methods (textContent), never innerHTML with
   pasted content, so a malicious email cannot inject code into this page.
   -------------------------------------------------------------------------- */

var GAUGE_CIRCUMFERENCE = 2 * Math.PI * 70; /* r = 70 in the SVG */

function el(tag, className, text) {
  var node = document.createElement(tag);
  if (className) { node.className = className; }
  if (text !== undefined && text !== null) { node.textContent = text; }
  return node;
}

function renderFindings(result, listEl, noFindingsEl, introEl) {
  listEl.textContent = '';

  if (result.findings.length === 0) {
    introEl.textContent = '';
    noFindingsEl.hidden = false;
    return;
  }

  noFindingsEl.hidden = true;
  introEl.textContent = 'Found ' + result.findings.length + ' warning sign' +
    (result.findings.length === 1 ? '' : 's') + ', most serious first.';

  for (var i = 0; i < result.findings.length; i++) {
    var f = result.findings[i];
    var item = el('li', 'finding sev-' + f.severity);

    var head = el('div', 'finding-head');
    head.appendChild(el('p', 'finding-title', f.title));
    var right = el('div', 'finding-head-right');
    right.appendChild(el('span', 'severity-chip', f.severity));
    right.appendChild(el('span', 'points-badge', '+' + f.points + ' pts'));
    head.appendChild(right);
    item.appendChild(head);

    item.appendChild(el('p', 'finding-why', f.why));

    var evLabel = el('span', 'evidence-label', 'What triggered this');
    item.appendChild(evLabel);
    var evBox = el('div', 'evidence');
    for (var j = 0; j < f.evidence.length; j++) {
      evBox.appendChild(el('code', null, f.evidence[j]));
    }
    item.appendChild(evBox);

    var adv = el('p', 'finding-advice');
    adv.appendChild(el('strong', null, 'What to do: '));
    adv.appendChild(document.createTextNode(f.advice));
    item.appendChild(adv);

    listEl.appendChild(item);
  }
}

function renderBreakdown(result, listEl) {
  listEl.textContent = '';
  var i;

  for (i = 0; i < result.findings.length; i++) {
    var f = result.findings[i];
    var row = el('li');
    row.appendChild(el('span', 'bk-name', f.title + '  (' + f.category + ')'));
    row.appendChild(el('span', 'bk-pts', '+' + f.points));
    listEl.appendChild(row);
  }

  if (result.findings.length === 0) {
    var emptyRow = el('li');
    emptyRow.appendChild(el('span', 'bk-name', 'No rules triggered'));
    emptyRow.appendChild(el('span', 'bk-pts', '+0'));
    listEl.appendChild(emptyRow);
  }

  var totalRow = el('li', 'bk-total');
  var totalLabel = 'Total score';
  if (result.capped) {
    totalLabel = 'Raw total ' + result.rawTotal + ', capped at ' + SCORE_MAX;
  }
  totalRow.appendChild(el('span', 'bk-name', totalLabel));
  totalRow.appendChild(el('span', 'bk-pts', String(result.score)));
  listEl.appendChild(totalRow);
}

function renderAdvice(result, listEl) {
  listEl.textContent = '';
  var recs = buildRecommendations(result);
  for (var i = 0; i < recs.length; i++) {
    listEl.appendChild(el('li', null, recs[i]));
  }
}

function updateGauge(score) {
  var progress = document.getElementById('gaugeProgress');
  var clamped = Math.max(0, Math.min(100, score));
  var offset = GAUGE_CIRCUMFERENCE * (1 - clamped / 100);

  progress.style.strokeDasharray = String(GAUGE_CIRCUMFERENCE);
  /* start empty, then animate to the target value */
  progress.style.strokeDashoffset = String(GAUGE_CIRCUMFERENCE);
  void progress.getBoundingClientRect();
  progress.style.strokeDashoffset = String(offset);

  var svg = progress.ownerSVGElement;
  if (svg) { svg.setAttribute('aria-label', 'Risk score ' + clamped + ' out of 100'); }
}

function renderResults(result) {
  var resultsEl = document.getElementById('results');
  var info = BAND_INFO[result.band];

  resultsEl.classList.remove('band-low', 'band-suspicious', 'band-high');
  resultsEl.classList.add('band-' + result.band);

  document.getElementById('scoreValue').textContent = String(result.score);
  document.getElementById('bandChip').textContent = info.label;
  document.getElementById('verdictTitle').textContent = info.label;
  document.getElementById('verdictText').textContent = info.verdict;

  var plural = result.findings.length === 1 ? '' : 's';
  document.getElementById('resultStats').textContent =
    'Analysed ' + result.meta.length.toLocaleString() + ' characters \u00b7 ' +
    result.findings.length + ' warning sign' + plural +
    ' detected \u00b7 analysis ran locally in your browser';

  renderFindings(result,
    document.getElementById('findingsList'),
    document.getElementById('noFindings'),
    document.getElementById('findingsIntro'));
  renderAdvice(result, document.getElementById('adviceList'));
  renderBreakdown(result, document.getElementById('scoreBreakdown'));

  resultsEl.hidden = false;
  updateGauge(result.score);
  if (resultsEl.scrollIntoView) {
    resultsEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

function updateCharCount() {
  var input = document.getElementById('emailInput');
  document.getElementById('charCount').textContent =
    input.value.length.toLocaleString() + ' characters';
}

function runAnalysis() {
  var input = document.getElementById('emailInput');
  var errorEl = document.getElementById('inputError');
  var resultsEl = document.getElementById('results');

  if (!input.value || !input.value.trim()) {
    errorEl.textContent = 'Please paste the contents of an email first, or load one of the fictional examples.';
    errorEl.hidden = false;
    resultsEl.hidden = true;
    input.focus();
    return null;
  }

  errorEl.hidden = true;
  var result = analyzeEmail(input.value);
  renderResults(result);
  return result;
}

function clearAll() {
  var input = document.getElementById('emailInput');
  input.value = '';
  updateCharCount();
  document.getElementById('inputError').hidden = true;
  document.getElementById('results').hidden = true;
  input.focus();
}

function loadSample(key) {
  var text = SAMPLES[key];
  if (!text) { return; }
  var input = document.getElementById('emailInput');
  input.value = text;
  updateCharCount();
  runAnalysis();
}

function initUI() {
  var input = document.getElementById('emailInput');
  var analyseBtn = document.getElementById('analyseBtn');
  var clearBtn = document.getElementById('clearBtn');
  var sampleWrap = document.getElementById('sampleButtons');

  /* If the page markup is not present (for example on the test page), do nothing. */
  if (!input || !analyseBtn || !clearBtn || !sampleWrap) { return; }

  input.addEventListener('input', updateCharCount);
  analyseBtn.addEventListener('click', runAnalysis);
  clearBtn.addEventListener('click', clearAll);

  sampleWrap.addEventListener('click', function (event) {
    var target = event.target;
    while (target && target !== sampleWrap) {
      if (target.getAttribute && target.getAttribute('data-sample')) {
        loadSample(target.getAttribute('data-sample'));
        return;
      }
      target = target.parentNode;
    }
  });

  /* Ctrl+Enter (or Cmd+Enter on a Mac) also starts the analysis. */
  input.addEventListener('keydown', function (event) {
    if ((event.ctrlKey || event.metaKey) && event.key === 'Enter') {
      event.preventDefault();
      runAnalysis();
    }
  });

  updateCharCount();
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', initUI);
} else {
  initUI();
}

/* Exposed so the self-test page (tests.html) can use the same engine. */
window.PhishingAnalyser = {
  analyzeEmail: analyzeEmail,
  buildRecommendations: buildRecommendations,
  RULES: RULES,
  SAMPLES: SAMPLES,
  BAND_INFO: BAND_INFO
};