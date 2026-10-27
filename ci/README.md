# CI recipes

`freebsd-prebuilt.yml` is the FreeBSD amd64 prebuilt workflow intended for
`.github/workflows/freebsd-prebuilt.yml`.

The GitHub OAuth token used for the initial publish lacked the `workflow`
scope, so the file ships here. To enable CI:

```sh
mkdir -p .github/workflows
cp ci/freebsd-prebuilt.yml .github/workflows/
git add .github/workflows/freebsd-prebuilt.yml
git commit -m "ci: enable FreeBSD prebuilt workflow"
git push
```

(Requires a token/PAT with the `workflow` scope, or commit via the GitHub UI.)
