# SonarQube Cloud

Each product repository is bound to its `durable-workflow_<repository>` project
in the Durable Workflow organization. Its README badge links to the actual
project gate. Private projects remain private.

## CI and credentials

`sonar-project.properties` owns source/test classification and exclusions.
`sonar.yml` scans main pushes and same-repository pull requests using the
reviewed official scanner. The job waits for the quality gate and fails on a
failed analysis or gate. Forks receive no Sonar credential. Their ordinary
checks still run; maintainers review and analyze changes on a trusted branch
before merging. Do not use `pull_request_target` to bypass this boundary.

Keep `SONAR_TOKEN` in repository Actions secrets and only expose it to the
scanner step. Disable Automatic Analysis when enabling CI analysis; running
both methods causes conflicts. Repositories using Automatic Analysis instead
configure source/test boundaries in `.sonarcloud.properties`. Review the exact
revision's findings alongside its normal qualification before merging or deploying.

## Quality settings

Use the maintained Sonar quality profiles and the built-in Sonar way gate.
It checks new security, reliability and maintainability ratings, reviewed
security hotspots, at most 3% duplication and 80% coverage on new code where
coverage applies. The current Free plan does not permit custom quality gates.

A first main analysis may report **Not Computed**. Configure its new-code
comparison baseline and analyze again before calling the gate operational.
The baseline does not resolve existing findings or mean that the overall
backlog is clean.

Existing repository test/coverage gates remain authoritative. The shared guide's
own scan imports a genuine coverage report from that job. Product scans currently
perform static analysis: `sonar.coverage.exclusions` leaves the uncollected
coverage metric unmeasured, while runtime code remains included in security,
reliability, maintainability and duplication analysis. This avoids publishing
zero coverage for code whose tests ran elsewhere. To add coverage to a scan,
produce a real report from the same source and replace this metric exclusion
with its report path. Do not exclude runtime code from analysis or accept
findings simply to make a badge green.

Tests and qualification fixtures are classified as tests. Generated assets,
third-party dependencies and temporary build/storage outputs are excluded.
Examples that customers run remain source unless they are explicitly test
harnesses. Adjust exclusions when the repository structure changes.

## Findings and notifications

Keep PR summary comments, inline annotations and GitHub checks enabled. They
deliver findings through the existing GitHub inbox. Maintainers handle those
reports and inspect the detailed Sonar issue before merging or releasing.
Fix valid defects with appropriate tests; record a concrete reason when marking
a false positive or accepting a risk. A passed gate does not replace review,
functional tests, dependency audits or release qualification.

Use the Sonar API/dashboard to investigate affected code and the exact revision.
Treat security findings according to their actual inputs and reachability.
Local HTTP fixtures, deliberate failure cases and generated data should not be
reported as vulnerabilities in shipped application paths.
