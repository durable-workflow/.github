import asyncio
import importlib.metadata
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

from dbos import DBOSClient

ROOT = Path('/evidence')
process = None
log = (ROOT / 'worker.log').open('a')


def snapshot(value):
    return value if isinstance(value, dict) else vars(value)


def start_worker():
    global process
    (ROOT / 'worker-ready').unlink(missing_ok=True)
    process = subprocess.Popen([sys.executable, 'worker.py'], stdout=log, stderr=subprocess.STDOUT)


def events(token):
    path = ROOT / 'events.jsonl'
    return [row for line in path.read_text().splitlines()
            if (row := json.loads(line))['token'] == token] if path.exists() else []


async def wait_for(token, stage, timeout=20):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        found = [row for row in events(token) if row['stage'] == stage]
        if found:
            return found[-1]
        if process.poll() is not None:
            raise RuntimeError('DBOS worker exited unexpectedly')
        await asyncio.sleep(0.02)
    raise RuntimeError('Missing ' + stage)


async def ready():
    until = time.monotonic() + 20
    while time.monotonic() < until:
        if (ROOT / 'worker-ready').exists():
            return
        if process.poll() is not None:
            raise RuntimeError('Worker failed before ready')
        await asyncio.sleep(0.05)
    raise RuntimeError('Worker did not become ready')


async def case(client, mode, repetition, kill_cleanup=False, duplicate=False):
    token = 'comparison-' + uuid.uuid4().hex
    arg = dict(token=token, mode=mode)
    handle = await client.enqueue_async(dict(workflow_name='parent', queue_name='comparison',
        workflow_id=token, app_version='cancellation-comparison-v1'), arg)
    await wait_for(token, 'callback.started')
    requested = time.monotonic()
    await client.cancel_workflow_async(token, cancel_children=True)
    status_at_reply = (await handle.get_status()).status
    compensation_handle = None
    killed_pid = replacement_pid = None
    if mode == 'detached':
        await wait_for(token, 'callback.exited')
        compensation_handle = await client.enqueue_async(dict(workflow_name='compensation',
            queue_name='comparison', workflow_id=token + '-compensation',
            app_version='cancellation-comparison-v1'), arg)
        await wait_for(token, 'compensation.entered')
        # Wait for the entered step to be committed before killing its worker.
        until = time.monotonic() + 5
        while len(await client.list_workflow_steps_async(token + '-compensation')) < 2:
            if time.monotonic() >= until:
                raise RuntimeError('Compensation entry did not commit')
            await asyncio.sleep(0.02)
    if kill_cleanup:
        if mode == 'step_cleanup':
            await wait_for(token, 'step.cleanup.entered')
        killed_pid = process.pid
        os.kill(process.pid, signal.SIGKILL)
        process.wait(timeout=5)
        start_worker()
        await ready()
    if duplicate:
        await client.cancel_workflow_async(token, cancel_children=True)
    if mode == 'detached':
        await asyncio.wait_for(compensation_handle.get_result(), 20)
        await wait_for(token, 'compensation.completed')
    elif not kill_cleanup:
        await wait_for(token, 'callback.exited')
        if mode == 'workflow_cleanup':
            await wait_for(token, 'root.cleanup.refused')
            await wait_for(token, 'child.cleanup.refused')
    else:
        # Cancelled runs are terminal, unlike a separately pending compensation.
        await asyncio.sleep(4)
    if kill_cleanup:
        replacement_pid = process.pid
    child_handle = await client.retrieve_workflow_async(token + '-child')
    rows = events(token)
    parent_status = await handle.get_status()
    child_status = await child_handle.get_status()
    row = dict(token=token, mode=mode, repetition=repetition, requested=requested,
        status_at_reply=status_at_reply, parent_status=snapshot(parent_status),
        child_status=snapshot(child_status), killed_pid=killed_pid,
        replacement_pid=replacement_pid, duplicate=duplicate, events=rows,
        parent_steps=[snapshot(step) for step in await client.list_workflow_steps_async(token)],
        child_steps=[snapshot(step) for step in await client.list_workflow_steps_async(token + '-child')],
        compensation_status=snapshot(await compensation_handle.get_status()) if compensation_handle else None,
        compensation_steps=[snapshot(step) for step in await client.list_workflow_steps_async(token + '-compensation')] if compensation_handle else [])
    with (ROOT / 'results.jsonl').open('a') as output:
        output.write(json.dumps(row, default=str) + '\n')
    print(json.dumps(dict(mode=mode, repetition=repetition, status_at_reply=status_at_reply,
        parent=parent_status.status, child=child_status.status,
        stages=[event['stage'] for event in rows], killed_pid=killed_pid,
        replacement_pid=replacement_pid, duplicate=duplicate)), flush=True)
    assert parent_status.status == child_status.status == 'CANCELLED', row
    assert row['child_steps'] == [], row
    if mode != 'sync':
        assert not any(event['stage'] == 'callback.late_effect' for event in rows), row
    if kill_cleanup:
        assert killed_pid != replacement_pid, row
    if mode == 'detached':
        assert row['compensation_status']['status'] == 'SUCCESS', row
        assert sum(event['stage'] == 'compensation.entered' for event in rows) == 1, row
        assert sum(event['stage'] == 'compensation.completed' for event in rows) == 1, row
        assert rows[-1]['monotonic'] - requested < 30, row
    elif mode == 'sync':
        assert any(event['stage'] == 'callback.late_effect' for event in rows), row
    elif mode == 'step_cleanup' and kill_cleanup:
        assert not any(event['stage'] == 'step.cleanup.completed' for event in rows), row
    elif mode == 'workflow_cleanup':
        assert not any(event['stage'].endswith('.cleanup.completed') for event in rows), row
    else:
        assert any(event['stage'] == 'step.cleanup.completed' for event in rows), row


async def main():
    start_worker()
    try:
        await ready()
        client = DBOSClient(system_database_url='sqlite:////tmp/state.sqlite')
        print(json.dumps(dict(package=importlib.metadata.version('dbos'))), flush=True)
        for mode in ('step_cleanup', 'sync', 'workflow_cleanup', 'detached'):
            for repetition in range(1, 4):
                await case(client, mode, repetition)
        for mode in ('step_cleanup', 'detached'):
            for repetition in range(1, 4):
                await case(client, mode, repetition, kill_cleanup=True)
        for repetition in range(1, 4):
            await case(client, 'detached', repetition, duplicate=True)
    finally:
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        log.close()


asyncio.run(main())
