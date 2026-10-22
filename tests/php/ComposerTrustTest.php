<?php

declare(strict_types=1);

use DurableWorkflow\Ci\ComposerTrust;
use DurableWorkflow\Ci\TrustRefused;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

require_once dirname(__DIR__, 2).'/.github/actions/verify-composer-trust/verify.php';

final class ComposerTrustTest extends TestCase
{
    private string $directory;
    private string $bundle;
    private string $composer;
    private array $saved = [];

    protected function setUp(): void
    {
        $this->directory = sys_get_temp_dir().'/composer-trust-'.bin2hex(random_bytes(8));
        mkdir($this->directory);
        mkdir($this->directory.'/empty');
        mkdir($this->directory.'/home');
        $this->bundle = $this->directory.'/roots.pem';
        file_put_contents($this->bundle, self::certificate('CI test root'));
        $this->composer = getenv('COMPOSER_BINARY') ?: trim((string) shell_exec('command -v composer'));
        foreach (array_merge(ComposerTrust::FILE_VARIABLES, ComposerTrust::OPTIONAL_FILE_VARIABLES, ComposerTrust::DIRECTORY_VARIABLES, ['DW_CI_CA_SHA256', 'COMPOSER_HOME', 'COMPOSER', 'GITHUB_ACTIONS']) as $name) {
            $this->saved[$name] = [getenv($name), $_SERVER[$name] ?? null, $_ENV[$name] ?? null];
            $this->environment($name);
        }
        foreach (ComposerTrust::FILE_VARIABLES as $name) {
            $this->environment($name.'='.$this->bundle);
        }
        foreach (ComposerTrust::DIRECTORY_VARIABLES as $name) {
            $this->environment($name.'='.$this->directory.'/empty');
        }
        $this->environment('DW_CI_CA_SHA256='.hash_file('sha256', $this->bundle));
        $this->environment('COMPOSER_HOME='.$this->directory.'/home');
    }

    protected function tearDown(): void
    {
        foreach ($this->saved as $name => [$value, $server, $env]) {
            putenv($value === false ? $name : $name.'='.$value);
            if ($server === null) { unset($_SERVER[$name]); } else { $_SERVER[$name] = $server; }
            if ($env === null) { unset($_ENV[$name]); } else { $_ENV[$name] = $env; }
        }
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->directory, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
        foreach ($iterator as $file) {
            $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
        }
        rmdir($this->directory);
    }

    private function environment(string $entry): void
    {
        putenv($entry);
        $parts = explode('=', $entry, 2);
        if (count($parts) === 1) {
            unset($_SERVER[$parts[0]], $_ENV[$parts[0]]);
        } else {
            $_SERVER[$parts[0]] = $_ENV[$parts[0]] = $parts[1];
        }
    }

    private static function certificate(string $subject): string
    {
        $key = openssl_pkey_new(['private_key_bits' => 2048]);
        $request = openssl_csr_new(['commonName' => $subject], $key, ['digest_alg' => 'sha256']);
        $certificate = openssl_csr_sign($request, null, $key, 1);
        openssl_x509_export($certificate, $pem);
        return $pem;
    }

    private function verify(): array
    {
        return ComposerTrust::verify($this->composer, $this->directory);
    }

    public function testActualComposerUsesTheAuthenticatedFileAndNoAdditionalRoots(): void
    {
        $result = $this->verify();
        self::assertSame(realpath($this->bundle), $result['ca_file']);
        self::assertSame(realpath($this->directory.'/empty'), $result['ca_directory']);
        self::assertSame(hash_file('sha256', $this->bundle), $result['sha256']);
        self::assertSame(1, $result['certificates']);
        self::assertSame([0, 0], array_values($result['blocked_roots']));
    }

    public static function missingOverrides(): array
    {
        return array_map(static fn (string $name): array => [$name], array_merge(ComposerTrust::FILE_VARIABLES, ComposerTrust::DIRECTORY_VARIABLES));
    }

    #[DataProvider('missingOverrides')]
    public function testPartialOverridesCannotFallBackToTheRawRunnerStore(string $name): void
    {
        $this->environment($name);
        $this->expectException(TrustRefused::class);
        $this->verify();
    }

    public function testDifferentCleanFileIsStillRefused(): void
    {
        copy($this->bundle, $this->directory.'/different.pem');
        $this->environment('CURL_CA_BUNDLE='.$this->directory.'/different.pem');
        $this->expectExceptionMessage('same regular file');
        $this->verify();
    }

    public function testModifiedAuthenticatedContentsAreRefused(): void
    {
        file_put_contents($this->bundle, self::certificate('Another root'));
        $this->expectExceptionMessage('differs from the authenticated');
        $this->verify();
    }

    public function testExtraDirectoryRootsAreRefused(): void
    {
        copy($this->bundle, $this->directory.'/empty/extra.pem');
        $this->expectExceptionMessage('same empty directory');
        $this->verify();
    }

    public static function blockedSubjects(): array
    {
        return [['AAA Certificate Services'], ['emSign ECC Root CA - G3']];
    }

    #[DataProvider('blockedSubjects')]
    public function testBlockedRootIsRefusedEvenWithMatchingFileMetadata(string $subject): void
    {
        file_put_contents($this->bundle, self::certificate($subject));
        $this->environment('DW_CI_CA_SHA256='.hash_file('sha256', $this->bundle));
        $this->expectExceptionMessage('Blocked certificate');
        $this->verify();
    }

    public function testMalformedCertificateIsRefused(): void
    {
        file_put_contents($this->bundle, "-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----");
        $this->environment('DW_CI_CA_SHA256='.hash_file('sha256', $this->bundle));
        $this->expectExceptionMessage('Malformed certificate');
        $this->verify();
    }

    public function testAProjectCannotDisableTls(): void
    {
        file_put_contents($this->directory.'/composer.json', '{"config":{"disable-tls":true}}');
        $this->expectExceptionMessage('must remain enabled');
        $this->verify();
    }

    public function testEnvironmentOverridesWinOverProjectCaPaths(): void
    {
        file_put_contents($this->directory.'/composer.json', '{"config":{"cafile":"old.pem","capath":"old-roots"}}');
        self::assertSame(realpath($this->bundle), $this->verify()['ca_file']);
    }

    public static function unsupportedVersions(): array
    {
        return [['2.9.9'], ['2.10.2'], ['3.0.0']];
    }

    #[DataProvider('unsupportedVersions')]
    public function testUnsupportedComposerVersionsAreRefused(string $version): void
    {
        $this->expectException(TrustRefused::class);
        ComposerTrust::requireVersion($version);
    }

    public function testCliReportsSuccessAndRefusalWithoutPrintingConfigurationSecrets(): void
    {
        $script = dirname(__DIR__, 2).'/.github/actions/verify-composer-trust/verify.php';
        $run = function () use ($script): array {
            $process = proc_open([PHP_BINARY, $script, $this->composer, $this->directory], [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
            $stdout = stream_get_contents($pipes[1]);
            $stderr = stream_get_contents($pipes[2]);
            fclose($pipes[1]);
            fclose($pipes[2]);
            return [proc_close($process), $stdout, $stderr];
        };
        [$status, $stdout] = $run();
        self::assertSame(0, $status);
        self::assertSame(realpath($this->bundle), json_decode($stdout, true, flags: JSON_THROW_ON_ERROR)['ca_file']);
        file_put_contents($this->directory.'/composer.json', '{secret-marker-not-for-logs');
        $this->environment('GITHUB_ACTIONS=true');
        [$status, $stdout, $stderr] = $run();
        self::assertSame(1, $status);
        self::assertStringContainsString('::error title=Composer trust refusal::', $stdout);
        self::assertStringNotContainsString('secret-marker-not-for-logs', $stdout.$stderr);
    }
}
