import asyncio
import json
import os
import time
from pathlib import Path

from dbos import DBOS, SetWorkflowID, error as dbos_error

ROOT = Path('/evidence')


def observe(token, stage, **extra):
    with (ROOT / 'events.jsonl').open('a') as output:
        output.write(json.dumps(dict(token=token, stage=stage, pid=os.getpid(),
                                     monotonic=time.monotonic(), **extra)) + '\n')


@DBOS.step()
async def mark(token, stage):
    observe(token, stage)


@DBOS.step(preemptible=True)
async def async_work(arg):
    observe(arg['token'], 'callback.started')
    try:
        until = time.monotonic() + 12
        while time.monotonic() < until:
            await asyncio.sleep(0.02)
        observe(arg['token'], 'callback.late_effect')
        return 'late-result'
    finally:
        if arg['mode'] == 'step_cleanup':
            observe(arg['token'], 'step.cleanup.entered')
            await asyncio.shield(asyncio.sleep(3))
            observe(arg['token'], 'step.cleanup.completed')
        observe(arg['token'], 'callback.exited')


@DBOS.step()
def sync_work(arg):
    observe(arg['token'], 'callback.started')
    try:
        time.sleep(12)
        observe(arg['token'], 'callback.late_effect')
        return 'late-result'
    finally:
        observe(arg['token'], 'callback.exited')


async def workflow_cleanup(arg, stage):
    observe(arg['token'], stage + '.cleanup.attempted')
    try:
        await asyncio.shield(mark(arg['token'], stage + '.cleanup.entered'))
        await asyncio.shield(DBOS.sleep_async(3))
        await asyncio.shield(mark(arg['token'], stage + '.cleanup.completed'))
    except (dbos_error.DBOSWorkflowCancelledError, Exception) as failure:
        observe(arg['token'], stage + '.cleanup.refused', exception=type(failure).__name__)


@DBOS.workflow()
async def child(arg):
    try:
        if arg['mode'] == 'sync':
            return await asyncio.to_thread(sync_work, arg)
        return await async_work(arg)
    finally:
        if arg['mode'] == 'workflow_cleanup':
            await workflow_cleanup(arg, 'child')


@DBOS.workflow()
async def parent(arg):
    try:
        with SetWorkflowID(arg['token'] + '-child'):
            handle = await DBOS.start_workflow_async(child, arg)
        return await handle.get_result()
    finally:
        if arg['mode'] == 'workflow_cleanup':
            await workflow_cleanup(arg, 'root')


@DBOS.workflow()
async def compensation(arg):
    await mark(arg['token'], 'compensation.entered')
    await DBOS.sleep_async(3)
    await mark(arg['token'], 'compensation.completed')


async def main():
    (ROOT / 'worker-ready').write_text(str(os.getpid()))
    await asyncio.Event().wait()


DBOS(config=dict(name='cancellation-comparison',
    application_version='cancellation-comparison-v1', executor_id='local',
    system_database_url='sqlite:////tmp/state.sqlite',
    run_admin_server=False, enable_otlp=False, log_level='WARNING'))
DBOS.launch()
DBOS.register_queue('comparison')
try:
    asyncio.run(main())
finally:
    DBOS.destroy()
