# Contributing to Crypto_Framework — Issue Workflow Guide

This guide explains how contributors should work on assigned issues and submit their changes to the project.

---

## 1. Fork & Clone the Repository

If you haven't already, fork the repository on GitHub and clone your fork locally:

```bash
git clone https://github.com/<your-username>/Crypto_Framework.git
cd Crypto_Framework
```

Add the upstream (original) repository as a remote so you can stay in sync:

```bash
git remote add upstream https://github.com/Amal-N47h/Crypto_Framework.git
```

---

## 2. Create a New Branch

Always work on a dedicated branch — **never commit directly to `main`**.

Name your branch using the following format:

```
week_<week-number>_<yourname>
```

**Examples:**
- `week_1_alice`
- `week_2_bob`
- `week_3_carol`

Create and switch to your branch:

```bash
git checkout -b week_1_yourname
```

---

## 3. Pull the Latest Changes from `main` into Your Branch

Before you start working (and periodically while working), make sure your branch is up to date with the latest `main`:

```bash
# Fetch the latest changes from upstream
git fetch upstream

# Merge upstream/main into your branch
git merge upstream/main
```

> **Tip:** Doing this regularly reduces the chance of large conflicts later.

---

## 4. Work on Your Issue

Make your changes, commit them with clear messages:

```bash
git add .
git commit -m "week_1_yourname: brief description of changes"
```

Keep commits small and focused so they are easy to review.

---

## 5. Push Your Branch to GitHub

Once your work is complete, push your branch to your fork:

```bash
git push origin week_1_yourname
```

---

## 6. Create a Pull Request (PR)

1. Go to the repository on GitHub.
2. Click **"Compare & pull request"** (GitHub usually shows this banner after you push a branch).
3. Set the **base branch** to `main` and the **compare branch** to `week_1_yourname`.
4. Fill in the PR title and description:
   - **Title:** `week_1_yourname — short summary`
   - **Description:** What issue you solved, what changes you made, and any notes for the reviewer.
5. Click **"Create pull request"**.

A maintainer will review your PR and merge it when it is approved.

---

## 7. Merge vs. Rebase — Which Should You Use?

Both `merge` and `rebase` integrate changes from one branch into another, but they work differently.

### `git merge`
- **What it does:** Creates a new *merge commit* that joins the histories of both branches.
- **History:** Preserves the complete, original history — you can always see exactly when branches diverged and were joined.
- **When to use it:** When you want to bring `main` into your feature branch to stay up to date, or when merging a finished PR into `main`.

```bash
# While on your feature branch, merge the latest main
git fetch upstream
git merge upstream/main
```

### `git rebase`
- **What it does:** Moves (replays) your commits on top of another branch's latest commit, rewriting history to appear linear.
- **History:** Creates a cleaner, linear history — easier to read in `git log`.
- **When to use it:** When you want a clean history before opening a PR and **you have not yet pushed / shared your branch with others**.

```bash
# While on your feature branch, rebase onto the latest main
git fetch upstream
git rebase upstream/main
```

> ⚠️ **Important:** Never rebase a branch that has already been pushed and shared with others. Rewriting shared history causes conflicts for everyone working on that branch. Use `merge` in that case.

### Quick Reference

| Scenario | Recommended command |
|---|---|
| Stay up to date with `main` on a shared/pushed branch | `git merge upstream/main` |
| Clean up local commits before opening a PR (not yet pushed) | `git rebase upstream/main` |
| Merge a finished PR into `main` | Use GitHub's **Merge pull request** button |

---

## Summary Checklist

- [ ] Fork & clone the repository
- [ ] Add `upstream` remote
- [ ] Create a branch named `week_<number>_<yourname>`
- [ ] Pull the latest `main` into your branch before starting
- [ ] Make changes and commit with clear messages
- [ ] Push your branch to your fork
- [ ] Open a Pull Request targeting `main`
- [ ] Address reviewer feedback
- [ ] Branch is merged 🎉
