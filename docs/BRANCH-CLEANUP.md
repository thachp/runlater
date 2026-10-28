# Merged branch cleanup preflight

Deleting a merged branch can auto-close another open PR that uses it as a stack base. This happened to PR #49: GitHub recorded base_ref_deleted at 2026-10-28 11:08:18 UTC, then closed at 11:08:19. Its client commit was preserved. Verify stack dependencies before branch deletion, not only whether the candidate's own PR merged.

1. Through the connected GitHub source, fetch repository/default-branch identity, the merged PR's exact head/merge status and current candidate ref.
2. Fetch **all pages** of currently open PRs. List every PR whose base equals the candidate branch, and every PR whose head equals it. Preserve each open PR's current head SHA and confirm its source ref still resolves, including forks where applicable.
3. If any open PR uses the branch as its base, stop deletion. Coordinate separately authorized retarget/rebase with its owner first. Re-fetch the PR and exact head; preserve its commits/review context. Never create a replacement PR merely to clear the preflight, and never treat close-unmerged as completion.
4. Only after dependent PRs are safely retargeted and verified, fetch fresh complete inventory/ref observations again. Ensure the candidate still equals the exact reviewed merged head, and it is neither the default/protected branch nor any unmerged PR head. Unknown/missing/truncated observations block deletion. Confirm the candidate is unprotected through provider metadata; unknown protection is a refusal, never an invitation to force a deletion.
5. Prefer a deletion primitive conditioned on the expected old object ID; a read-only snapshot is not an atomic concurrency guard. If no conditional primitive is available, recheck immediately and stop on any changed/uncertain state. Delete only the independently authorized exact candidate; verify absence and confirm all preserved open PRs remain open with their expected heads. If state changed or the outcome is uncertain, reconcile before any retry. No force deletion or unrelated branch cleanup.

The read-only offline validator below has no network, subprocess, Git, retarget or deletion capability. It checks an operator-collected snapshot, not provider truth. `eligible: true` is not authorization or a guarantee against a concurrent change. Its five-minute freshness ceiling is an upper bound; recheck immediately before mutation. Inventory completeness and ref observations must come from fresh provider reads, never be asserted just to get a green result.

```sh
node scripts/branch-cleanup-preflight.mjs < /private/path/cleanup-snapshot.json
node --test scripts/branch-cleanup-preflight.test.mjs
```

Input shape (SHAs/time below are illustrative and deliberately not current evidence):

```json
{
  "repository": "thachp/runlater",
  "defaultBranch": "main",
  "branch": "feat/merged",
  "observedAt": "2026-10-28T12:00:00Z",
  "completeOpenPrInventory": true,
  "expectedMergedHead": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "mergedPullRequest": {
    "repository": "thachp/runlater", "number": 46, "merged": true, "base": "main",
    "head": {"repository": "thachp/runlater", "ref": "feat/merged", "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
    "mergeCommitSha": "cccccccccccccccccccccccccccccccccccccccc"
  },
  "candidateRef": {"protected": false, "ref": "refs/heads/feat/merged", "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
  "openPullRequests": [{
    "number": 49, "state": "open", "base": "feat/merged",
    "head": {"repository": "thachp/runlater", "ref": "feat/client", "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}
  }],
  "observedPrHeadRefs": [{"repository": "thachp/runlater", "ref": "refs/heads/feat/client", "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}]
}
```

This example is blocked because PR49 depends on the candidate base. Missing head preservation, unmerged/wrong PR, changed candidate SHA, incomplete/stale/future inventory and default-branch targets also block. The tool returns exit 2 on refusal/invalid input and exit 0 only for internal snapshot consistency. It neither searches for credentials nor logs private repository content; use only repository/ref/PR metadata, never keys or tokens.
