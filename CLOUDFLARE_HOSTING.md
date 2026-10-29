# Portfolio hosting

The public site is https://collinbgeorge.com/, served by the static-assets Worker `collinbgeorge-portfolio` in the existing Sanctir, LLC Cloudflare account. Both apex and www are bound to this Worker. Domain registration remains at Squarespace; authoritative DNS is Cloudflare. Mail and verification records are preserved.

GitHub Pages is retired. The Full HTML portfolio workflow builds, verifies and uploads a `cloudflare-static-site` artifact. Download and extract that artifact, then upload its contents using New deployment in the existing Cloudflare Worker. Deployment is manual; merging a change does not automatically publish it. No Cloudflare API credentials are stored here.

The CM-2026 source snapshot is read from its pinned Git commit via git archive, allowing builds in this private repository. Other project snapshots and dependency integrity checks remain pinned. Public website pages and their intentional source downloads remain public even though this hosting repository is private.
