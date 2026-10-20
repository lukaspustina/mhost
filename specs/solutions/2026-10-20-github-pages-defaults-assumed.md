---
class: unverified-claim-treated-as-fact
repeat-of: none
---
# The cutover assumed GitHub Pages defaults it did not have

**What failed.** `specs/features/docs-site/spec.md` planned "old Pages off, new Pages on" and tag
deploys from `website.yml`. Two defaults did not hold: GitHub creates the `github-pages`
environment with a deployment rule for `master` only, so `deploy-pages` rejects every `v*` tag
("Tag … is not allowed to deploy to github-pages due to environment protection rules"); and
`DELETE repos/lukaspustina/mhost.pustina.de/pages` answered 422 "Deactivating GitHub pages for this
repository is not allowed." for legacy Pages built from `gh-pages`.
**What worked.** `gh api -X POST repos/<owner>/<repo>/environments/github-pages/deployment-branch-policies -f name='v*' -f type=tag`
after enabling Pages, and releasing the old custom domain with `PUT …/pages` and `cname: null`
instead of deactivating it. The leftover legacy copy under `<owner>.github.io/<old-repo>` renders
broken (built for `baseUrl: '/'`).
**How to notice next time.** A spec line about a hosted platform's behaviour carries "assumed" or
cites no read of the live API; read the environment and Pages endpoints before writing the step.
