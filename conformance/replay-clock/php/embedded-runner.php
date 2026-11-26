<?php

declare(strict_types=1);

// Replay the shared replay-clock vectors through the installed Workflow
// package's worker-protocol runner (WorkflowFiberRunner, used by external PHP
// workers). The embedded executor itself reads the run row's started_at, the
// column the carrier is built from; this runner receives it as replayClock.

require_once __DIR__.'/vendor/autoload.php';

use Composer\InstalledVersions;
use Workflow\V2\Support\WorkflowFiberRunner;
use Workflow\V2\Workflow;

final class ReplayClockConformanceWorkflow extends Workflow
{
    public static string $activity = '';

    public static int $seconds = 0;

    /** @return array<string, mixed> */
    public function handle(): array
    {
        $read = static fn (): string => Workflow::now()->utc()->format('Y-m-d\TH:i:s.u\Z');
        $entry = $read();
        $repeated = $read() === $entry;
        Workflow::activity(self::$activity);
        $afterActivity = $read();
        Workflow::timer(self::$seconds);

        return [
            'entry' => $entry,
            'repeated_reads_equal' => $repeated,
            'after_activity' => $afterActivity,
            'after_timer' => $read(),
        ];
    }
}

$vectors = json_decode((string) file_get_contents($argv[1]), true, flags: JSON_THROW_ON_ERROR);
$spec = $vectors['workflow'];
ReplayClockConformanceWorkflow::$activity = $spec['activity_type'];
ReplayClockConformanceWorkflow::$seconds = $spec['timer_seconds'];

$micros = static function (?string $text): ?int {
    if ($text === null) {
        return null;
    }
    $time = DateTimeImmutable::createFromFormat('Y-m-d\TH:i:s.u\Z', $text, new DateTimeZone('UTC'));

    return $time === false ? null : (int) $time->format('U') * 1_000_000 + (int) $time->format('u');
};

$observations = [];
foreach ($vectors['cases'] as $case) {
    $step = WorkflowFiberRunner::forClass(
        ReplayClockConformanceWorkflow::class,
        $spec['workflow_id'],
        $spec['run_id'],
        $spec['input'],
        $spec['payload_codec'],
        $vectors['history'],
        replayClock: $case['replay_clock'] ?? null,
    )->step();
    if (! $step->completed || ! is_array($step->result)) {
        fwrite(STDERR, "{$case['id']}: the runner did not complete\n");
        exit(1);
    }
    $observed = $step->result;
    $start = $micros($observed['after_activity']);
    $end = $micros($observed['after_timer']);
    $observed['elapsed_microseconds'] = $start === null || $end === null ? null : $end - $start;
    $observations[$case['id']] = $observed;
}

echo json_encode([
    'binding' => 'embedded-worker-protocol',
    'sdk_version' => InstalledVersions::getPrettyVersion('durable-workflow/workflow'),
    'observations' => $observations,
], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES), "\n";
