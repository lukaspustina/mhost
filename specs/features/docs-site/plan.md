# Plan: docs-site

## Phase 1 — Sources in website/

### Groups

G1: C1, C4, C10, C11 · G2: C2, C3, C12, C13 · G3: C5, C14 · G4: C6, C16 · G5: C7, C17 · G6: C9, C18 · G7: C8, C15

G1 first: every other group needs `website/`. G2–G5 touch one file each. G6 and G7 change no file; they are checks after G1–G5.

### Plan

- **G1** — `git -C ~/Documents/src/mhost.pustina.de archive ccc96d5 docs src static sidebars.js babel.config.js docusaurus.config.js | tar -x -C website` (keeps `static/.nojekyll`); no Makefile, README, package*.json, .gitignore. In `website/docusaurus.config.js`: `projectName: 'mhost'`, `editUrl: 'https://github.com/lukaspustina/mhost/edit/master/website/'`; `url` unchanged.
- **G2** — `website/package.json` from the old one: every dependency exact-pinned (Docusaurus newest 3.x, React/react-dom newest 19.x, the rest exact), `engines.node` `>=24`, no `deploy` script; `website/package-lock.json` via `npm install` (network); `website/.nvmrc` = `24`.
- **G3** — `website/README.md`, new text: Docusaurus 3, `just site-install|site-build|site-serve`, deploy by `.github/workflows/website.yml` on `v*` tags and `workflow_dispatch`; no `npm run deploy`, `USE_SSH`, `gh-pages`, Docusaurus 2.
- **G4** — `.gitignore`: `website/node_modules/`, `website/build/`, `website/.docusaurus/`.
- **G5** — `justfile`: `# --- website ---` section before `# --- project-specific ---` with `site-install` (`npm ci` in `website/`), `site-build`, `site-serve`; no existing recipe changes.
- **G6** — no change; `cargo package --list --allow-dirty | grep '^website/'` empty.
- **G7** — no change; `just site-install && just site-build` exits 0, `website/build/index.html` exists, `git status --porcelain` clean under the ignored dirs.

## Phase 2 — Deploy workflow

### Groups

G1: C1, C3, C4, C5 · G2: C2, C6, C7 · C8 is a guard, no change. G1 and G2 share no file.

### Plan

- **G1** — `.github/workflows/website.yml` (new): `on: push: tags: ['v*']` and `workflow_dispatch`; `permissions` `contents: read`, `pages: write`, `id-token: write`; `concurrency: { group: pages, cancel-in-progress: false }`; job `build`: checkout, `actions/setup-node` with `node-version-file: website/.nvmrc` and npm cache on `website/package-lock.json`, `npm ci` and `npm run build` with `working-directory: website`, `actions/upload-pages-artifact` with `path: website/build`; job `deploy` (needs build, environment `github-pages`): `actions/deploy-pages`. Style of the existing workflows (yamllint header, `---`).
- **G2** — `.github/workflows/ci.yml`: `paths-ignore: ['website/**']` under `push` and `pull_request`; branches and the `!v*` tag filter unchanged.
