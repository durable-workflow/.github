# Durable Workflow

**Durable execution for PHP, Python, and Rust.**

Durable Workflow keeps long-running application code moving through process
restarts, retries, timers, and human input. Workflows and activities are written
in ordinary application code while the runtime records history and resumes work
without repeating completed steps.

[Documentation](https://durable-workflow.com/) |
[Sample App](https://github.com/durable-workflow/sample-app) |
[Durable Workflow Cloud](https://cloud.durable-workflow.com/) |
[Self-hosted Server](https://github.com/durable-workflow/server)

## Choose how to run

| Mode | Best fit | You operate |
| --- | --- | --- |
| [Durable Workflow Cloud](https://cloud.durable-workflow.com/) | Managed orchestration for PHP, Python, and Rust applications | Your SDK clients and workers |
| [Self-hosted Server](https://github.com/durable-workflow/server) | Language-neutral orchestration in your own infrastructure | Server, persistence, Waterline, and SDK workers |
| [Embedded Laravel](https://durable-workflow.com/docs/2.0/category/embedded/) | Laravel applications that want the runtime inside the application boundary | Your Laravel application, queues, and database |

## First-party SDKs

| Language | Guide and API reference | Source | Package |
| --- | --- | --- | --- |
| PHP | [php.durable-workflow.com](https://php.durable-workflow.com/) | [`sdk-php`](https://github.com/durable-workflow/sdk-php) | [`durable-workflow/sdk`](https://packagist.org/packages/durable-workflow/sdk) |
| Python | [python.durable-workflow.com](https://python.durable-workflow.com/) | [`sdk-python`](https://github.com/durable-workflow/sdk-python) | [`durable-workflow`](https://pypi.org/project/durable-workflow/) |
| Rust | [rust.durable-workflow.com](https://rust.durable-workflow.com/) | [`sdk-rust`](https://github.com/durable-workflow/sdk-rust) | [`durable-workflow`](https://crates.io/crates/durable-workflow) |

The SDKs share workflow and activity type names, task queues, namespaces, and a
portable Avro value protocol. A workflow in one language can dispatch an
activity to a worker in another.

## Runtime capabilities

- Durable workflows and activities with retries, timeouts, and heartbeats
- Timers, schedules, signals, queries, and updates
- Child workflows, sagas, cancellation, and continue-as-new
- Namespaces, search attributes, memo, and workflow history
- [Waterline](https://github.com/durable-workflow/waterline) for operational visibility and control
- [`dw`](https://github.com/durable-workflow/cli) for command-line operation

Start with the [2.0 documentation](https://durable-workflow.com/docs/2.0/) or
open the [Sample App](https://github.com/durable-workflow/sample-app) for
runnable embedded and service-mode examples.
