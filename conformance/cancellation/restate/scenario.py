import json
import os
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

import httpx

ROOT = Path('/evidence')
client = httpx.Client(timeout=5)
process = None
service_log = (ROOT / 'service.log').open('a')


def start():
    global process
    process = subprocess.Popen([sys.executable, 'service.py'], stdout=service_log,
                               stderr=subprocess.STDOUT)
    until = time.monotonic() + 15
    while time.monotonic() < until:
        try:
            response = client.get('http://sdk:9080/health')
            if response.status_code in (200, 404):
                return
        except httpx.HTTPError:
            pass
        time.sleep(0.1)
    raise RuntimeError('SDK endpoint did not become ready')


def events(token):
    path = ROOT / 'events.jsonl'
    if not path.exists():
        return []
    return [row for line in path.read_text().splitlines()
            if (row := json.loads(line))['token'] == token]


def wait_for(token, stage, timeout):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        found = [row for row in events(token) if row['stage'] == stage]
        if found:
            return found[-1]
        time.sleep(0.05)
    raise RuntimeError('Missing ' + stage + ' for ' + token)


def query(sql):
    response = client.post('http://restate:9070/query', json={'query': sql},
                           headers={'Accept': 'application/json'})
    response.raise_for_status()
    return response.json()


def case(mode, repetition, kill_cleanup=False, duration=12, duplicate_request=False):
    token = 'comparison-' + uuid.uuid4().hex
    arg = dict(token=token, mode=mode, duration=duration, kill_cleanup=kill_cleanup,
               duplicate_during_cleanup=duplicate_request)
    response = client.post(f'http://restate:8080/CancellationRoot/{token}/run/send', json=arg)
    response.raise_for_status()
    submitted = response.json()
    invocation = submitted['invocationId']
    ready = 'leaf.wait.started' if mode == 'durable_wait' else 'leaf.callback.started'
    wait_for(token, ready, 15)
    requested = time.monotonic()
    accepted = client.patch(f'http://restate:9070/invocations/{invocation}/cancel')
    accepted.raise_for_status()
    duplicate = None
    if duplicate_request:
        wait_for(token, 'root.cleanup.entered', 20)
        duplicate = client.patch(f'http://restate:9070/invocations/{invocation}/cancel')
        duplicate.raise_for_status()
    killed_pid = None
    replacement_pid = None
    if kill_cleanup:
        wait_for(token, 'root.cleanup.entered', 20)
        killed_pid = process.pid
        os.kill(killed_pid, signal.SIGKILL)
        process.wait(timeout=5)
        start()
        replacement_pid = process.pid
    until = time.monotonic() + max(35, duration + 10)
    while time.monotonic() < until:
        observed = events(token)
        invocation_ids = sorted({event['invocation_id'] for event in observed if 'invocation_id' in event})
        call_graph = query("SELECT * FROM sys_invocation WHERE id IN (" +
                           ','.join("'" + value + "'" for value in invocation_ids) + ")")
        rows = call_graph['rows']
        if len(rows) == 3 and all(item['status'] == 'completed' for item in rows):
            break
        time.sleep(0.1)
    observed = events(token)
    completed = [event for event in observed if event['stage'] == 'root.cleanup.completed']
    callback_exit = None
    settled = time.monotonic() - requested
    if mode in ('async_run', 'sync_run'):
        callback_exit = wait_for(token, 'leaf.callback.exited', duration + 10)
        observed = events(token)
    row = dict(mode=mode, repetition=repetition, token=token, request_monotonic=requested,
               submitted=submitted, cancel_status=accepted.status_code,
               cancel_body=accepted.text, duplicate_status=duplicate.status_code if duplicate is not None else None,
               duplicate_body=duplicate.text if duplicate is not None else None,
               cleanup_elapsed=completed[-1]['monotonic'] - requested if completed else None,
               cascade_settled_elapsed=settled,
               cascade_completed=len(rows) == 3 and all(item['status'] == 'completed' for item in rows),
               callback_stop_observed=callback_exit is not None,
               callback_exit_elapsed=callback_exit['monotonic'] - requested if callback_exit else None,
               late_effect_observed=any(event['stage'] == 'leaf.callback.late_effect' for event in observed),
               duplicate_during_cleanup=duplicate_request,
               killed_pid=killed_pid, replacement_pid=replacement_pid, events=observed)
    # Query the durable invocation projection, not just application log entries.
    time.sleep(0.2)
    row['durable_invocations'] = query("SELECT * FROM sys_invocation WHERE id = '" + invocation + "'")
    invocation_ids = sorted({event['invocation_id'] for event in row['events'] if 'invocation_id' in event})
    row['call_graph'] = query("SELECT * FROM sys_invocation WHERE id IN (" +
                             ','.join("'" + value + "'" for value in invocation_ids) + ")")
    with (ROOT / 'results.jsonl').open('a') as output:
        output.write(json.dumps(row) + '\n')
    print(json.dumps({key: row[key] for key in (
        'mode', 'repetition', 'cascade_completed', 'cleanup_elapsed',
        'callback_exit_elapsed', 'late_effect_observed', 'duplicate_during_cleanup',
        'killed_pid', 'replacement_pid'
    )}), flush=True)


try:
    start()
    response = client.post('http://restate:9070/deployments', json={'uri': 'http://sdk:9080'})
    response.raise_for_status()
    (ROOT / 'deployment.json').write_text(json.dumps(response.json(), indent=2))
    if len(sys.argv) > 1 and sys.argv[1] == 'duplicate':
        for repetition in range(1, 4):
            case('durable_wait', repetition, duplicate_request=True, duration=12)
    elif len(sys.argv) > 1 and sys.argv[1] == 'callback':
        for mode in ('async_run', 'sync_run'):
            for repetition in range(1, 4):
                case(mode, repetition)
    else:
        for mode in ('durable_wait', 'async_run', 'sync_run'):
            for repetition in range(1, 4):
                case(mode, repetition)
        for repetition in range(1, 4):
            case('durable_wait', repetition, kill_cleanup=True)
finally:
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    service_log.close()
    client.close()
