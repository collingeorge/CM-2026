# Website security review - 29 October 2026

Scope: CM-2026 static-site builder, generated website, hosted MCAT runtime, pinned source exports, GitHub build workflow and collinbgeorge.com Cloudflare TLS settings. This is a scoped code/configuration review, not an independent penetration test or a guarantee that all vulnerabilities are absent.

## Remediation

- Replaced regex-only removal of active source HTML with a parser-based tag/attribute allowlist and decoded-URL protocol validation. Script, form, embedded document, SVG/MathML and event-handler source markup cannot run in reading pages.
- Added scoped Content-Security-Policy, anti-framing, MIME-sniffing protection, referrer and browser capability restrictions. Retained source downloads are sandboxed when opened in the browser.
- Corrected the hosted MCAT service-worker cache cleanup prefix so it cleans its own old caches and does not target the original app's cache namespace.
- Cloudflare: Always Use HTTPS enabled; minimum TLS 1.2; TLS 1.3 enabled; Full (Strict) certificate validation. Managed edge certificates show Active.
- Enabled HSTS for 12 months with includeSubDomains and preload off, preserving unverified unrelated subdomains.
- Added repeatable security validation to the GitHub build.

## Verification

Local build: 208 reading documents, eight projects, 38 diagram definitions, 251 retained source files. Link/anchor validation: 219 pages, zero missing files, zero missing anchors, zero duplicate IDs. Security regression run: 288 checks, zero errors. The checks include eight hostile-HTML examples, pinned-source SHA-256 comparison, first-party JavaScript syntax checks and required-header presence. They are counts of scoped assertions, not vulnerability coverage.

Live Cloudflare deployment a5816817: SecurityHeaders.com reports A+ for the custom-domain homepage and workers.dev homepage with the intended CSP and HSTS. That rating covers headers only. Direct shell HTTP/TLS probing is blocked by Windows socket policy (WinError 10013), including after network permission; no claim of exhaustive cipher/protocol negotiation testing is made.

## Residual limitations

- MCAT uses inline event handlers and dynamic HTML assembled from its curated question bank. Its path-scoped CSP requires unsafe-inline; unsafe-eval is not allowed. Removing this exception requires an event-binding refactor and behavioral regression validation.
- Styles allow unsafe-inline for Mermaid and app presentation. Main portfolio scripts are restricted to self.
- Browser certificate pinning (HPKP) is deprecated and is not implemented. Normal CA certificate validation, managed renewal, HTTPS redirection and HSTS are used. Pinning Cloudflare's rotating edge certificate would be unsuitable.
- Dependency versions are pinned and archive-integrity checked (Mermaid 12.2.0; Marked 17.0.5). Publisher advisory pages were consulted; this was not a complete transitive software-composition analysis.
- No backend, accounts or server-side patient data handling are implemented by this static site. MCAT progress is browser-local and is not suitable for sensitive health records.
- DNSSEC was off at the registrar during migration; DNSSEC enablement/DS publication remains a separate incomplete setup step.
- Repository privacy and retirement of temporary GitHub Pages fallback remain migration tasks; this report does not assert they are complete.

References:
https://developers.cloudflare.com/workers/static-assets/headers/
https://secure-headers-project.owasp.org/response-headers/
https://github.com/mermaid-js/mermaid/security/advisories
https://github.com/markedjs/marked/security/advisories
