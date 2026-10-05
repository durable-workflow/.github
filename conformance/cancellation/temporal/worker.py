import asyncio
import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
from pathlib import Path

from temporalio import activity, workflow
from temporalio.client import Client
from temporalio.common import RetryPolicy
from temporalio.exceptions import is_cancelled_exception
from temporalio.worker import Worker

ROOT = Path('/evidence')


def observe(token, stage, **extra):
    row = dict(token=token, stage=stage, monotonic=time.monotonic(), pid=os.getpid(), **extra)
    with (ROOT / 'events.jsonl').open('a') as output:
        output.write(json.dumps(row) + '\n')


@activity.defn
def mark(arg: dict) -> None:
    observe(arg['token'], arg['stage'], reason=arg.get('reason'))


def started(arg):
    info = activity.info()
    observe(arg['token'], 'callback.started', local=info.is_local,
            task_token=info.task_token.hex(), attempt=info.attempt)


@activity.defn
async def async_work(arg: dict) -> str:
    started(arg)
    until = time.monotonic() + 12
    try:
        while time.monotonic() < until:
            if arg['heartbeat']:
                activity.heartbeat('working')
            await asyncio.sleep(0.02)
        observe(arg['token'], 'callback.late_effect')
        return 'late-result'
    finally:
        observe(arg['token'], 'callback.exited')


@activity.defn
def sync_work(arg: dict) -> str:
    started(arg)
    try:
        time.sleep(12)
        observe(arg['token'], 'callback.late_effect')
        return 'late-result'
    finally:
        observe(arg['token'], 'callback.exited')


async def cleanup(arg, stage):
    await workflow.execute_local_activity(mark, dict(token=arg['token'], stage=stage + '.cleanup.entered',
        reason=workflow.cancellation_reason()), start_to_close_timeout=timedelta(seconds=5),
        retry_policy=RetryPolicy(maximum_attempts=1))
    if stage == 'root' and (arg['kill_cleanup'] or arg['duplicate']):
        await asyncio.sleep(3)
    await workflow.execute_local_activity(mark, dict(token=arg['token'], stage=stage + '.cleanup.completed'),
        start_to_close_timeout=timedelta(seconds=5), retry_policy=RetryPolicy(maximum_attempts=1))


@workflow.defn
class Child:
    @workflow.run
    async def run(self, arg: dict) -> str:
        try:
            callback = sync_work if arg['sync'] else async_work
            options = dict(start_to_close_timeout=timedelta(seconds=30),
                cancellation_type=workflow.ActivityCancellationType.WAIT_CANCELLATION_COMPLETED,
                retry_policy=RetryPolicy(maximum_attempts=1))
            if arg['local']:
                result = await workflow.execute_local_activity(callback, arg, **options)
            else:
                if arg['heartbeat']:
                    options['heartbeat_timeout'] = timedelta(seconds=2)
                result = await workflow.execute_activity(callback, arg, **options)
            if workflow.cancellation_reason() is not None:
                raise asyncio.CancelledError()
            return result
        except BaseException as error:
            if not is_cancelled_exception(error):
                raise
            await asyncio.shield(cleanup(arg, 'child'))
            raise


@workflow.defn
class Parent:
    @workflow.run
    async def run(self, arg: dict) -> str:
        try:
            result = await workflow.execute_child_workflow(Child.run, arg,
                id=arg['token'] + '-child',
                cancellation_type=workflow.ChildWorkflowCancellationType.WAIT_CANCELLATION_COMPLETED,
                parent_close_policy=workflow.ParentClosePolicy.REQUEST_CANCEL,
                task_timeout=timedelta(seconds=2))
            if workflow.cancellation_reason() is not None:
                raise asyncio.CancelledError()
            return result
        except BaseException as error:
            if not is_cancelled_exception(error):
                raise
            await asyncio.shield(cleanup(arg, 'root'))
            raise


async def main():
    client = await Client.connect('temporal:7233')
    with ThreadPoolExecutor(max_workers=4) as executor:
        async with Worker(client, task_queue='cancellation-comparison', workflows=[Parent, Child],
            activities=[mark, async_work, sync_work], activity_executor=executor,
            sticky_queue_schedule_to_start_timeout=timedelta(seconds=2),
            max_heartbeat_throttle_interval=timedelta(milliseconds=100),
            default_heartbeat_throttle_interval=timedelta(milliseconds=100)):
            await asyncio.Event().wait()


if __name__ == '__main__':
    asyncio.run(main())
