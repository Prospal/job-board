# Security Job Board

Daily scraper for cyber security jobs (remote, plus onsite in Singapore, Japan, the Gulf and other
English-speaking hubs with relocation), with a dashboard on GitHub Pages.

- `scraper.py` pulls jobs from company career APIs (Greenhouse, Lever, Ashby, Workday),
  Gulf boards (Bayt, GulfTalent), LinkedIn's public search and remote boards (Remotive, RemoteOK, Jobicy).
- `.github/workflows/scrape.yml` runs it every day at 01:00 UTC and commits encrypted `docs/jobs.csv.enc` + `docs/jobs.json.enc`.
- `docs/index.html` is the dashboard (filters, apply links, per-browser status tracking).

The job data is encrypted (AES-256, PBKDF2) with the `DASHBOARD_PASSWORD` repository secret before it is
committed, so only `docs/*.enc` is public; the dashboard asks for that password and decrypts in the browser.
Running `scraper.py` locally writes plain files to `data/` (git-ignored).

Edit the CONFIG block at the top of `scraper.py` to change companies, countries, keywords and skills.

## Private files / new computer

CVs and applications live in a separate **private** repo, cloned into `private/` (ignored by this repo):

```bash
gh repo clone Prospal/job-board
cd job-board
gh repo clone Prospal/job-private private
```

## Dashboard password

The dashboard password **is** the `DASHBOARD_PASSWORD` secret. GitHub never shows a secret again after
it is saved, so keep it in a password manager.

**Forgot it, or want to change it:**

1. Set a new one (you type it at the prompt):
   ```bash
   gh secret set DASHBOARD_PASSWORD --repo Prospal/job-board
   ```
   Or on the web: repo → Settings → Secrets and variables → Actions → `DASHBOARD_PASSWORD` → Update.
2. Re-encrypt the data with the new password by running the workflow now:
   ```bash
   gh workflow run scrape.yml --repo Prospal/job-board
   ```
   Or: repo → Actions → Scrape jobs → Run workflow.
3. After it finishes (~5–10 min), open the dashboard and log in with the new password.
   If the old one was remembered on a device, press **Log out** first.

The old encrypted history can't be read with the new password, so each job's `first_seen` date
resets once. Everything else carries on normally.
