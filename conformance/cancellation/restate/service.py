import asyncio
import json
import logging
import os
import time
from datetime import timedelta
from pathlib import Path

import restate

logging.basicConfig(level=logging.INFO)
ROOT = Path('/evidence')
root = restate.Workflow('CancellationRoot')
child = restate.Workflow('CancellationChild')
leaf = restate.Service('CancellationLeaf')


def observe(token, stage, **extra):
    row = dict(token=token, stage=stage, monotonic=time.monotonic(),
               wall=time.time(), pid=os.getpid(), **extra)
    with (ROOT / 'events.jsonl').open('a') as output:
        output.write(json.dumps(row) + '\n')
        output.flush()


async def async_callback(arg):
    observe(arg['token'], 'leaf.callback.started')
    try:
        await asyncio.sleep(arg['duration'])
        observe(arg['token'], 'leaf.callback.late_effect')
        return 'late-result'
    finally:
        observe(arg['token'], 'leaf.callback.exited')


def sync_callback(arg):
    observe(arg['token'], 'leaf.callback.started')
    try:
        time.sleep(arg['duration'])
        observe(arg['token'], 'leaf.callback.late_effect')
        return 'late-result'
    finally:
        observe(arg['token'], 'leaf.callback.exited')


async def compensate(ctx, arg, stage, error):
    # Follow the documented TerminalError -> durable compensation -> rethrow.
    await ctx.run_typed(stage + '.cleanup.entered', observe,
                        token=arg['token'], stage=stage + '.cleanup.entered', error=str(error))
    if stage == 'root' and (arg.get('kill_cleanup') or arg.get('duplicate_during_cleanup')):
        await ctx.sleep(timedelta(seconds=3))
    await ctx.run_typed(stage + '.cleanup.completed', observe,
                        token=arg['token'], stage=stage + '.cleanup.completed')


@leaf.handler()
async def work(ctx: restate.Context, arg: dict):
    observe(arg['token'], 'leaf.handler.entered', invocation_id=ctx.request().id)
    try:
        if arg['mode'] == 'durable_wait':
            await ctx.run_typed('leaf.ready', observe, token=arg['token'], stage='leaf.wait.started')
            await ctx.sleep(timedelta(seconds=60))
        elif arg['mode'] == 'async_run':
            await ctx.run_typed('leaf.callback', async_callback, arg=arg)
        else:
            await ctx.run_typed('leaf.callback', sync_callback, arg=arg)
        observe(arg['token'], 'leaf.handler.completed')
        return 'completed'
    except restate.TerminalError as error:
        await compensate(ctx, arg, 'leaf', error)
        raise


@child.main()
async def child_run(ctx: restate.WorkflowContext, arg: dict):
    observe(arg['token'], 'child.handler.entered', invocation_id=ctx.request().id)
    try:
        return await ctx.service_call(work, arg)
    except restate.TerminalError as error:
        await compensate(ctx, arg, 'child', error)
        raise


@root.main()
async def run(ctx: restate.WorkflowContext, arg: dict):
    observe(arg['token'], 'root.handler.entered', invocation_id=ctx.request().id)
    try:
        return await ctx.workflow_call(child_run, arg['token'] + '-child', arg)
    except restate.TerminalError as error:
        await compensate(ctx, arg, 'root', error)
        raise


app = restate.app(services=[root, child, leaf])

if __name__ == '__main__':
    from hypercorn.asyncio import serve
    from hypercorn.config import Config
    config = Config()
    config.bind = ['0.0.0.0:9080']
    asyncio.run(serve(app, config))
