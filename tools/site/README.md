# Full HTML portfolio build

This builder produces a portable static site from pinned public source snapshots. It preserves complete source files and renders documents as reading pages. Private drafts and shadowing material are excluded.

Run Python prepare.py, Node build-site.mjs, then Python check-site.py. The output is dist/. No server or framework is required to serve the result. Dependencies are fetched as exact versions and verified by SHA-512; source files are verified by SHA-256. Sources are not silently refreshed: update pins and integrity records deliberately after review.

The MCAT study app is not hosted by this build: it is served at https://mcat.collinbgeorge.com/ and every link to it points there. Its Markdown documents are rendered as reading pages; its source files are not republished under downloads/ (the pin sets "downloads": false) and link to the GitHub repository instead.

Pages are linked by clean URL, as Cloudflare static assets serve them by default: a directory index as the directory with a trailing slash, any other page without .html. Files under downloads/ keep their literal names. CSS and JavaScript under assets/ are referenced with ?v= set to the first 8 hex digits of the file's SHA-256 and are served with a one-year immutable Cache-Control; pages, search-index.json and sitemap.xml always revalidate.

Mermaid and marked license files are retained. Project-specific licenses remain alongside the source downloads. A presentation conversion is not a new clinical or statistical validation.
