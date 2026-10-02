---
name: push-only-to-own-github
description: "Never push to anyone else's GitHub repo (e.g. Lenilk/Cafe-wifi) — only the user's own lenulk/Cafe-wifi"
metadata:
  node_type: memory
  type: feedback
  originSessionId: 668bce67-4ec1-453a-add8-59fc42ac7deb
  modified: 2026-10-01T19:34:41.872Z
---

Only ever push to the user's own repo `https://github.com/lenulk/Cafe-wifi` (remote `origin`). Never push,
open PRs, or otherwise write to anyone else's GitHub repo — in particular the collaborator fork
`Lenilk/Cafe-wifi` ([[lenilk-fork]]). Fetching/reading from other repos is fine.

**Why:** user stated it explicitly on 2026-10-02 while reviewing Lenilk's fork.

**How to apply:** before any `git push`, check the destination is `origin` = lenulk/Cafe-wifi. Never add
another repo as a push target; fetch from it by URL instead. Pushing to our own repo still needs the user's
go-ahead (and fix/lenilk-review must not be merged until tested on the Pi).
