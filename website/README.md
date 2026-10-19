# mhost documentation site

Docusaurus 3 site for mhost. Node version: see `.nvmrc`.

```sh
just site-install   # npm ci in website/
just site-build     # static build into website/build/
just site-serve     # serve the built site locally
```

Deployed to GitHub Pages by `.github/workflows/website.yml` on `v*` release tags and on
`workflow_dispatch`.
