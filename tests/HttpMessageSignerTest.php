<?php
namespace HttpSignature\Tests;

use PHPUnit\Framework\TestCase;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use HttpSignature\HttpMessageSigner;
use HttpSignature\Tests\Helpers\RawHttpBuilder;

final class HttpMessageSignerTest extends TestCase
{
    private string $privateKey;
    private string $publicKey;
    private HttpMessageSigner $signer;

    protected function setUp(): void
    {
        $this->privateKey = file_get_contents(__DIR__ . '/keys/private.pem');
        $this->publicKey = file_get_contents(__DIR__ . '/keys/public.pem');

        $request = new Request('GET', '/');
        $response = new Response(200, ['Content-Type' => 'text/plain']);

        $this->signer = (new HttpMessageSigner($request, $response))
            ->setPrivateKey($this->privateKey)
            ->setPublicKey($this->publicKey)
            ->setKeyId('test-key')
            ->setAlgorithm('rsa-sha256');

    }

    public function testSignsAndVerifiesValidRequest(): void
    {
        $request = new Request(
            'POST',
            'https://api.example.com/resource?bat=&baz=3',
            [
                'Host' => ['api.example.com'],
                'Date' => [gmdate('D, d M Y H:i:s T')],
            ]
        );

        $this->signer->setRequest($request);
        $signed = $this->signer->signRequest(['@method', '@path', '@request-target', 'host', 'date', '@query-param;name=baz']);
        $this->signer->setRequest($signed);
        $this->assertTrue($signed->hasHeader('signature'));
        $this->assertTrue($signed->hasHeader('signature-input'));


        $isValid = $this->signer->verifyRequest($signed);
        $this->assertTrue($isValid, 'Signed request should be valid');
    }

    public function testSignsAndVerifiesWithBodyDigest(): void
    {
        $body = '{"message":"hello"}';
        $digest = $this->signer->createContentDigestHeader($body);

        $request = new Request(
            'POST',
            'https://example.com/api',
            ['Host' => ['example.com'], 'Content-Digest' => [$digest]],
            $body
        );

        $this->signer->setRequest($request);
        $signed = $this->signer->signRequest(['@method', '@path', 'host', 'content-digest']);
        $this->signer->setRequest($signed);
        $this->assertTrue($this->signer->verifyRequest($signed));
    }

    public function testFailsIfBodyDigestDoesNotMatch(): void
    {
        $originalBody = '{"message":"hello"}';
        $digest = $this->signer->createContentDigestHeader($originalBody);

        // Use a different body (tampered)
        $tamperedBody = '{"message":"goodbye"}';

        $request = new Request(
            'POST',
            'https://example.com/api',
            ['Host' => ['example.com'], 'Content-Digest' => [$digest]],
            $tamperedBody
        );

        $this->signer->setRequest($request);
        $signed = $this->signer->signRequest(['@method', '@path', 'host', 'content-digest']);
        $this->assertFalse($this->signer->verifyRequest($signed),
                'Digest mismatch should cause verification to fail');
    }


    public function testVerificationFailsWhenHeaderIsModified(): void
    {
        $request = new Request(
            'POST',
            'https://api.example.com/resource',
            [
                'Host' => ['api.example.com'],
                'Date' => [gmdate('D, d M Y H:i:s T')],
            ]
        );

        $this->signer->setRequest($request);
        $signed = $this->signer->signRequest(['@method', '@path', 'host', 'date']);
        $this->signer->setRequest($signed);
        $tampered = $signed->withHeader('Host', 'attacker.com');
        $this->signer->setRequest($tampered);

        $this->assertFalse($this->signer->verifyRequest($tampered), 
                                'Tampered request should be invalid');
    }

    public function testVerificationFailsWithoutSignature(): void
    {
        $request = new Request(
            'POST',
            'https://api.example.com/resource',
            [
                'Host' => ['api.example.com'],
                'Date' => [gmdate('D, d M Y H:i:s T')],
            ]
        );

        $this->signer->setRequest($request);
        $this->assertFalse($this->signer->verifyRequest($request),
                                'Unsigned request should be invalid');
    }

    public function testParsesRawHttpMessageCorrectly(): void
    {

        $raw = RawHttpBuilder::fromParts(
                'POST',
                '/foo',
                [
                        'Host'=>'example.com',
                        'Date'=>'Tue, 13 May 2025 00:00:01 GMT',
                        'Content-Type' => 'application/json',
                        'Content-Digest' => 'sha-256=:abcd1234=:'
                ],
                '{"message":"hello"}'
        );

        $parsed = HttpMessageSigner::parseHttpMessage($raw);

        $this->assertEquals('POST', $parsed['method']);
        $this->assertEquals('/foo', $parsed['path']);
        $this->assertEquals('example.com', $parsed['headers']['host']);
        $this->assertEquals('Tue, 13 May 2025 00:00:01 GMT', $parsed['headers']['date']);
        $this->assertEquals('application/json', $parsed['headers']['content-type']);
        $this->assertEquals('{"message":"hello"}', $parsed['body']);
    }

    public function testManualInpectSignature(): void
    {

        $request = new Request(
            'POST',
            'https://api.example.com/resource',
            [
                'Host' => ['api.example.com'],
                'Date' => [gmdate('D, d M Y H:i:s T')],
            ],
            '{"message":"hello"}'
        );

        $this->signer->setRequest($request);
        $digest = $this->signer->createContentDigestHeader((string) $request->getBody());
        $request = $request->withHeader('Content-Digest', $digest);
        $request = $this->signer->signRequest(['@method', '@path', 'host', 'date', 'content-digest']);

        echo "\n\nManual Inspection\n\n";

        foreach ($request->getHeaders() as $name => $values) {
            echo $name . ": " . implode(', ', $values) . PHP_EOL;
        }

        // Optional assertion to keep PHPUnit happy
        $this->assertTrue($request->hasHeader('signature'), 'Signature header should exist');
    }
 
    public function testSignsAndVerifiesParsedRawHttpMessage(): void
    {
        $body = '{"message":"hello"}';

        $raw = RawHttpBuilder::fromParts(
            'POST', 
            '/foo', 
            [
                'Host' => 'example.com',
                'Date' => gmdate('D, d M Y H:i:s T'),
            ], 
            $body);

        $parsed = HttpMessageSigner::parseHttpMessage($raw);
        $headers = $parsed['headers'];
        $method = $parsed['method'];
        $path = $parsed['path'];

        $headers['content-digest'] = $this->signer->createContentDigestHeader($body);

        $signed = $this->signer->sign($headers, [
            '@method',
            '@path',
            'host',
            'content-digest'
        ]);

        echo "\n\nManual Inspection\n\n";
        var_dump($signed);

        $this->assertArrayHasKey('signature', $signed);
        $this->assertArrayHasKey('signature-input', $signed);

        $isValid = $this->signer->verify($signed);

        $this->assertTrue($isValid, 'Signed and parsed raw message should verify');
    }
}

