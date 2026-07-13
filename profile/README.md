# Durable Workflow

[Durable Workflow](https://github.com/durable-workflow/server) is a platform for building, running, and managing long-running workflows across applications, services, and languages. It provides the core primitives for defining workflows, executing activities, tracking progress, handling failures, and coordinating work that must survive process restarts, queue delays, retries, and infrastructure changes.

A workflow represents a durable business or system process made up of ordered steps, decisions, timers, signals, queries, child workflows, and activities. Activities are the individual units of work executed by workers, services, scripts, agents, or external systems. Together, they let developers break complex processes into clear, reliable, and observable pieces.

Durable Workflow is designed for modern orchestration use cases, including agentic AI workflows, financial operations, data pipelines, microservice coordination, job tracking, user onboarding, scheduled automation, sagas, and other business-critical processes that need durable execution rather than best-effort background jobs.

Key capabilities include:

- Simple workflow and activity definitions using declarative application code.
- Durable execution for long-running processes that need to resume safely after failures.
- Support for queues, workers, retries, timers, signals, updates, and parallel execution.
- Tools for starting, monitoring, querying, managing, and repairing workflows.
- Integration with scalable worker infrastructure for asynchronous and distributed execution.
- Support for both [application-embedded](https://github.com/durable-workflow/workflow) workflows (Laravel only) and [server-backed](https://github.com/durable-workflow/server) orchestration across languages.
- Operational visibility for workflow history, task queues, worker health, failures, and runtime state.
- Documentation and ecosystem tooling for building reliable workflow-driven applications.

Durable Workflow helps teams move beyond fragile background jobs by providing a structured, observable, and resilient foundation for complex application workflows.
