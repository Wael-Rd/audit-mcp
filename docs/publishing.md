# Publish the project

The project's default branch is `main`. The CI workflow checks the project without deploying infrastructure or connecting to audit targets.

Run the checks in the README, inspect `git status`, and ensure your real `targets.yaml`, `.env`, `.runtime`, keys and audit outputs remain ignored. The synthetic preview and sample observation are safe, clearly marked public design fixtures. The supplied MIT license applies to the original project code and design.

Create your GitHub repository, then run:

```bash
git add .
git commit -m "feat: add ten-step confidentiality hardening MCP"
git remote add origin <your-github-repository-url>
git push -u origin main
```

The CI workflow uses pinned action revisions, locked dependencies, linting, regression tests, a publication scan, dependency audit and package build. It does not connect to your targets or receive target credentials.
