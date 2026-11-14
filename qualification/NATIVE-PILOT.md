# Native required-workflow pilot

This replaces the unprovisioned custom App design for #237. It creates no App,
key or check-writing credential. GitHub's organization rule requires the selected
central workflow; its result is not a caller-selected status-check name.

The source-only import file `native-policy-pilot.json` is **disabled**. Nothing
in a source merge applies the rule. It targets only the public `.github`
repository's default branch, with no bypass actors. Do not target all branches.
The organization is eligible for native required workflows. Applying the rule
needs existing authorized organization-admin access, which the current CLI
credential does not provide; do not silently expand OAuth scopes.

The workflow checks out only the literal reviewed central runtime commit. It
never checks out the candidate. The isolated, hash-locked parser and existing
bounded read-only API client read the exact public PR or merge-group commit's
workflow/helper blobs as nonexecutable data. The existing protected context and
shared policy checks remain unchanged. No App issuer or check-writing endpoint
is called. Both supported event types produce a failing job on refusal rather
than a successful skipped job. Private repositories are not silently onboarded.

The runtime pin is an earlier commit in the same reviewed source ancestry,
avoiding a circular self-hash. Updating protected policy or reader behavior needs
a reviewed runtime-pin update; do not assume the pin follows a moving branch.
The rule selects the central workflow from protected main. Protect changes to
that source and record the actual workflow/runtime commits in pilot evidence.

An upstream input disappearing can prevent the policy repository's own required
CI from admitting its repair. The old runtime also cannot admit new workflow
bytes or action pins. Do not disable the rule or add bypass actors to break
that cycle. Prepare and independently review the complete source successor,
including its exact workflow/action registries. The successor workflow must pin
an earlier reviewed runtime commit in the same ancestry. An authorized
organization administrator can then select that frozen workflow with the
ruleset's `sha` field while keeping enforcement Active and every other rule
unchanged. This administrative selection is separate from source review and
requires existing authorized access; never silently expand credential scopes.
Trigger fresh accepted and refused PR events to verify the new enforcer before
merging the repair through the protected path. Restore a moving main ref only
after verifying that it selects the same accepted workflow and runtime.

After source acceptance, the bounded live rollout is:

1. An authorized organization admin imports the disabled rule and verifies its
   repository ID, default-branch target and central workflow path/ref.
2. Select **Evaluate**, retaining all existing required checks. Use fresh PR
   events: GitHub does not automatically run a newly added requirement for an
   already-open PR. Do not fabricate a successful Check Run.
3. Verify actual required-workflow/source identity for a valid same-repository PR
   and a public fork; malformed inputs, stale head/base, wrong repository and
   rejected policy must fail. Confirm that candidate helpers were not executed
   and that an ordinary same-named check cannot satisfy the workflow rule.
4. Verify `merge_group` identity and combined-tree behavior before enabling the
   rule for a queued repository. Local models cover that path but are not a live
   merge-queue result. Source-access settings and event context must be observed,
   not inferred from a workflow file or a green ordinary PR check.
5. Only after the bounded pilot is accepted select **Active** for this one target.
   Retire obsolete App-pilot source separately; expand target repositories only
   after their visibility, compatibility and queue behavior are qualified.

Keep the existing protections and unset App environment entries throughout.
A failed evaluate run stays failed; fix its source before another selected
attempt. Rollback disables only this exact new rule, preserving existing rules.

Primary documentation:

- [Required workflows](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/available-rules-for-rulesets#require-workflows-to-pass-before-merging)
- [Events, source access and merge queues](https://docs.github.com/en/enterprise-cloud@latest/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/troubleshooting-rules#troubleshooting-ruleset-workflows)
- [Organization rule setup and evaluate mode](https://docs.github.com/en/enterprise-cloud@latest/organizations/managing-organization-settings/creating-rulesets-for-repositories-in-your-organization)
