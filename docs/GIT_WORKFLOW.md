# Git workflow for the team
Rules from the Axlero handbook: every member has their OWN branch and commits to it;
the team needs commits on 10 different days before the mid review and EVERY day for
the 20 days before the final review.

## One-time setup (each member)
```bash
git config --global user.name  "Your Name"
git config --global user.email "your-github-email"
git clone https://github.com/<lead-username>/api-sentinel.git
cd api-sentinel
git checkout -b m2-sniffer          # use your own branch name
git push -u origin m2-sniffer
```
GitHub asks for a Personal Access Token instead of a password
(Settings -> Developer settings -> Personal access tokens).

## Daily
```bash
git checkout <your-branch>
git pull origin <your-branch>
# ... work ...
git add .
git commit -m "Short, clear message"
git push origin <your-branch>
```
Commit before midnight so the commit counts for that day.

## Merging (team lead)
Open a Pull Request from your branch to `main` on GitHub; the lead reviews and merges.
If there is a conflict: `git pull origin main` into your branch, fix, push again.

## Never commit
Passwords, tokens, API keys, `.env` files.
