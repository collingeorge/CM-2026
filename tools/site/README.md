# Full HTML portfolio build

This builder produces a portable static site from pinned public source snapshots. It preserves complete source files and renders documents as reading pages. Private drafts and unauthorized shadowing material are excluded.

Run Python prepare.py, Node build-site.mjs, then Python check-site.py. The output is dist/. No server or framework is required to serve the result. Dependencies are fetched as exact versions and verified by SHA-512; source files are verified by SHA-256. Sources are not silently refreshed: update pins and integrity records deliberately after review.

The MCAT runtime is isolated under study/mcat/ with its own service-worker scope. Changing origins does not migrate browser-local study progress. The original app remains available at its previous URL.

Mermaid and marked license files are retained. Project-specific licenses remain alongside the source downloads. A presentation conversion is not a new clinical or statistical validation.
