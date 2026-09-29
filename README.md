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
