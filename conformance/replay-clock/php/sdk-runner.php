<?php

declare(strict_types=1);

// Replay the shared replay-clock vectors through the installed PHP service SDK.
// Reads vectors-v1.json from argv[1]; prints one JSON object mapping each case
// id to its observations. Times are UTC RFC 3339 with six fractional digits
// and Z; an unavailable read is null.

require_once __DIR__.'/vendor/autoload.php';

use Composer\InstalledVersions;
use DurableWorkflow\Client;
use DurableWorkflow\Codec\AvroPayloadCodec;
use DurableWorkflow\Exception\ReplayClockUnavailable;
use DurableWorkflow\Testing\InMemoryTransport;
use DurableWorkflow\Testing\WorkerTestHarness;
use DurableWorkflow\Worker;
use DurableWorkflow\Worker\WorkflowContext;

$vectors = json_decode((string) file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
$spec = $vectors['workflow'];

$read = static function (WorkflowContext $context): ?string {
    try {
        return $context->replayNow()->setTimezone(new DateTimeZone('UTC'))->format('Y-m-d\TH:i:s.u\Z');
    } catch (ReplayClockUnavailable) {
        return null;
    }
};

$client = new Client('http://durable-workflow.test', transport: new InMemoryTransport());
$worker = (new Worker($client, 'conformance', workerId: 'conformance'))
    ->registerWorkflow($spec['type'], static function (WorkflowContext $context) use ($read, $spec): array {
        $entry = $read($context);
        $repeated = $read($context) === $entry;
        $context->activity($spec['activity_type'], []);
        $afterActivity = $read($context);
        $context->sleep($spec['timer_seconds']);

        return [
            'entry' => $entry,
            'repeated_reads_equal' => $repeated,
            'after_activity' => $afterActivity,
            'after_timer' => $read($context),
        ];
    });
$harness = new WorkerTestHarness($worker);
$codec = new AvroPayloadCodec();

$micros = static function (?string $text): ?int {
    if ($text === null) {
        return null;
    }
    $time = DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.u\Z', $text, new DateTimeZone('UTC'));

    return $time === false ? null : (int) $time->format('U') * 1_000_000 + (int) $time->format('u');
};

$observations = [];
foreach ($vectors['cases'] as $case) {
    $task = ['workflow_id' => $spec['workflow_id'], 'run_id' => $spec['run_id']];
    if (array_key_exists('replay_clock', $case)) {
        $task['replay_clock'] = $case['replay_clock'];
    }
    $result = $harness->runWorkflow($spec['type'], $spec['input'], $vectors['history'], $task);
    $last = $result->commands[array_key_last($result->commands)] ?? null;
    if (count($result->commands) !== 1 || ($last['type'] ?? null) !== 'complete_workflow') {
        fwrite(STDERR, "{$case['id']}: expected one complete_workflow command\n");
        exit(1);
    }
    $observed = $codec->decodeEnvelope($last['result']);
    $start = $micros($observed['after_activity']);
    $end = $micros($observed['after_timer']);
    $observed['elapsed_microseconds'] = $start === null || $end === null ? null : $end - $start;
    $observations[$case['id']] = $observed;
}

echo json_encode([
    'binding' => 'php',
    'sdk_version' => InstalledVersions::getPrettyVersion('durable-workflow/sdk'),
    'observations' => $observations,
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), "\n";
