import asyncio
import json
import os
import signal
import subprocess
import sys
import time
import uuid
from datetime import timedelta
from pathlib import Path

from google.protobuf.json_format import MessageToDict
from temporalio.api.enums.v1 import EventType
from temporalio.api.workflowservice.v1 import DescribeNamespaceRequest, GetClusterInfoRequest
from temporalio.client import Client

from worker import Parent

ROOT = Path('/evidence')
process = None
log = (ROOT / 'worker.log').open('a')


def start_worker():
    global process
    process = subprocess.Popen([sys.executable, 'worker.py'], stdout=log, stderr=subprocess.STDOUT)


def events(token):
    path = ROOT / 'events.jsonl'
    return [row for line in path.read_text().splitlines()
            if (row := json.loads(line))['token'] == token] if path.exists() else []


async def wait_for(token, stage, seconds=20):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        found = [row for row in events(token) if row['stage'] == stage]
        if found:
            return found[-1]
        if process.poll() is not None:
            raise RuntimeError('Worker exited unexpectedly')
        await asyncio.sleep(0.02)
    raise RuntimeError('Missing ' + stage)


async def case(client, profile, repetition, kill_cleanup=False, duplicate=False):
    token = 'comparison-' + uuid.uuid4().hex
    arg = dict(token=token, local=profile.startswith('local'), sync=profile == 'local_sync',
               heartbeat=profile == 'remote_heartbeat', kill_cleanup=kill_cleanup, duplicate=duplicate)
    handle = await client.start_workflow(Parent.run, arg, id=token,
        task_queue='cancellation-comparison', task_timeout=timedelta(seconds=2))
    started = await wait_for(token, 'callback.started')
    requested = time.monotonic()
    await handle.cancel(reason='comparison cancellation')
    killed_pid = None
    replacement_pid = None
    stale_during_cleanup = None
    if kill_cleanup or duplicate:
        await wait_for(token, 'root.cleanup.entered')
        # Wait until the original cleanup timer is in canonical history.
        until = time.monotonic() + 5
        while time.monotonic() < until:
            history = await handle.fetch_history()
            if any(event.event_type == EventType.EVENT_TYPE_TIMER_STARTED for event in history.events):
                break
            await asyncio.sleep(0.02)
        else:
            raise RuntimeError('Root cleanup timer did not commit')
        try:
            await client.get_async_activity_handle(task_token=bytes.fromhex(started['task_token'])).complete('stale-during-cleanup')
            stale_during_cleanup = 'accepted'
        except Exception as error:
            stale_during_cleanup = type(error).__name__ + ': ' + str(error)
        if duplicate:
            await handle.cancel(reason='duplicate cancellation')
        if kill_cleanup:
            killed_pid = process.pid
            os.kill(killed_pid, signal.SIGKILL)
            process.wait(timeout=5)
            start_worker()
            replacement_pid = process.pid
    try:
        await asyncio.wait_for(handle.result(), timeout=35)
        result = 'returned'
    except Exception as error:
        result = type(error).__name__ + ': ' + str(error)
    stopped = await wait_for(token, 'callback.exited', 15)
    child = client.get_workflow_handle(token + '-child')
    parent_history = await handle.fetch_history()
    child_history = await child.fetch_history()
    rows = events(token)
    cleanup = [event for event in rows if event['stage'] == 'root.cleanup.completed']
    stale = None
    if not arg['local']:
        try:
            await client.get_async_activity_handle(task_token=bytes.fromhex(started['task_token'])).complete('stale-result')
            stale = 'accepted'
        except Exception as error:
            stale = type(error).__name__ + ': ' + str(error)
    row = dict(token=token, profile=profile, repetition=repetition, requested=requested,
        callback_exit_elapsed=stopped['monotonic'] - requested,
        cleanup_elapsed=cleanup[-1]['monotonic'] - requested if cleanup else None,
        late_effect=any(event['stage'] == 'callback.late_effect' for event in rows),
        parent_status=(await handle.describe()).status.name,
        child_status=(await child.describe()).status.name,
        result=result, stale_completion=stale, duplicate=duplicate,
        killed_pid=killed_pid, replacement_pid=replacement_pid,
        stale_during_cleanup=stale_during_cleanup, events=rows,
        parent_history=[MessageToDict(event) for event in parent_history.events],
        child_history=[MessageToDict(event) for event in child_history.events])
    with (ROOT / 'results.jsonl').open('a') as output:
        output.write(json.dumps(row) + '\n')
    print(json.dumps({key: row[key] for key in ('profile', 'repetition', 'parent_status', 'child_status',
        'callback_exit_elapsed', 'cleanup_elapsed', 'late_effect', 'duplicate', 'killed_pid', 'replacement_pid')}), flush=True)

    # Require the durable outcomes and physical observations, independently.
    assert row['parent_status'] == row['child_status'] == 'CANCELED', row
    assert cleanup and row['cleanup_elapsed'] < 30, row
    assert sum(event['stage'] == 'root.cleanup.entered' for event in rows) == 1, row
    assert sum(event['stage'] == 'root.cleanup.completed' for event in rows) == 1, row
    assert sum(event['stage'] == 'child.cleanup.entered' for event in rows) == 1, row
    assert sum(event['stage'] == 'child.cleanup.completed' for event in rows) == 1, row
    original = [event for event in row['parent_history']
                if event['eventType'] == 'EVENT_TYPE_WORKFLOW_EXECUTION_CANCEL_REQUESTED']
    assert len(original) == 1, original
    assert original[0]['workflowExecutionCancelRequestedEventAttributes']['cause'] == 'comparison cancellation', original
    if not arg['local']:
        assert stale is not None and stale != 'accepted', row
    if profile == 'remote_no_heartbeat':
        assert row['late_effect'] and row['callback_exit_elapsed'] > 10, row
    elif profile == 'local_sync':
        assert not row['late_effect'] and row['callback_exit_elapsed'] > 10, row
    else:
        assert not row['late_effect'], row
    if kill_cleanup:
        assert killed_pid != replacement_pid, row
    if kill_cleanup or duplicate:
        assert stale_during_cleanup is not None and stale_during_cleanup != 'accepted', row
        for event_type in ('EVENT_TYPE_TIMER_STARTED', 'EVENT_TYPE_TIMER_FIRED'):
            assert sum(event['eventType'] == event_type for event in row['parent_history']) == 1, row


async def main():
    until = time.monotonic() + 20
    while True:
        try:
            client = await Client.connect('temporal:7233')
            cluster = await client.workflow_service.get_cluster_info(GetClusterInfoRequest())
            await client.workflow_service.describe_namespace(DescribeNamespaceRequest(namespace='default'))
            break
        except Exception:
            if time.monotonic() >= until:
                raise
            await asyncio.sleep(0.1)
    (ROOT / 'cluster.json').write_text(json.dumps(MessageToDict(cluster), indent=2))
    versions = json.loads(Path('versions.json').read_text())
    assert cluster.server_version == versions['server'], cluster
    start_worker()
    try:
        for profile in ('remote_heartbeat', 'remote_no_heartbeat', 'local_async', 'local_sync'):
            for repetition in range(1, 4):
                await case(client, profile, repetition)
        for repetition in range(1, 4):
            await case(client, 'remote_heartbeat', repetition, kill_cleanup=True)
        for repetition in range(1, 4):
            await case(client, 'remote_heartbeat', repetition, duplicate=True)
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
