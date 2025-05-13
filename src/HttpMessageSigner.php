<?php

namespace HttpSignature;

use Psr\Http\Message\RequestInterface;

class HttpMessageSigner
{
    public function __construct(
        private string $keyId,
        private string $privateKey,
        private ?string $publicKey = null,
        private string $alg = 'rsa-sha256'        // default
    ) {}

    /* PSR-7 inteface to signing function (use sign() below for non-PSR-7 reqs) */

    public function signRequest(RequestInterface $request, 
                                 array $coveredFields): RequestInterface
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        $signedHeaders = $this->sign(
            $headers,
            $request->getMethod(),
            $request->getUri()->getPath(),
            $coveredFields
        );

        foreach (['signature-input', 'signature'] as $header) {
            $request = $request->withHeader($header, $signedHeaders[$header]);
        }

        return $request;
    }

    /* PSR-7 verify interface and also check body digest if included 
        use verify() for non PSR-7 reqs */

    public function verifyRequest(RequestInterface $request): bool
    {
        $headers = [];
        foreach ($request->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        /* check the body digest if it's present */

        if (isset($headers['content-digest'])) {
            $body = (string) $request->getBody();
            if (!$this->isBodyDigestValid($body, $headers['content-digest'])) {
                return false;
            }   
        }

        return $this->verify(
            $headers,
            $request->getMethod(),
            $request->getUri()->getPath()
        );
    }

    /* check body digest */

    private function isBodyDigestValid(string $body, string $headerValue): bool
    {
        if (!preg_match('/sha-256=:(.*?):/', $headerValue, $matches)) {
            return false;
        }

        $expectedDigest = base64_decode($matches[1]);
        $actualDigest = hash('sha256', $body, true);

        return hash_equals($expectedDigest, $actualDigest);
    }

    /* non-PSR-7 sign function, header names are made lowercase */

    public function sign(array $headers, string $method, string $path, 
                                array $coveredFields): array
    {
        $coveredFields = array_map('strtolower', $coveredFields);
        $signatureComponents = [];

        foreach ($coveredFields as $field) {
            $signatureComponents[] = $this->canonicalizeComponent($field, $headers, 
                                                                   $method, $path);
        }

        $paramList = implode(' ', array_map(fn($f) => '"'.$f.'"', $coveredFields));
        $signatureInput = '('.$paramList.');keyid="'.
                                $this->keyId.'";alg="'.$this->alg.'"';

        $signatureComponents[] = '"@signature-params": '.$signatureInput;

        $signatureBase = implode("\n", $signatureComponents);
        $signature = $this->createSignature($signatureBase);

        $headers['signature-input'] = "sig1=$signatureInput";
        $headers['signature'] = "sig1=:$signature:";

        return $headers;
    }

    /* non-PSR-7 verify() note: does not check body digest, 
        use verifyRequest if needed or calculate digest using helper functions, below
    */

    public function verify(array $headers, string $method, string $path): bool
    {
        if (!isset($headers['signature-input'], $headers['signature'])) {
            return false;
        }

        $sigInputDict = $this->parseStructuredDict($headers['signature-input']);
        $sigDict = $this->parseStructuredDict($headers['signature']);

        if (!isset($sigInputDict['sig1'], $sigDict['sig1'])) {
            return false;
        }

        [$fieldsList, $params] = $sigInputDict['sig1'];
        $coveredFields = array_map(fn($f) => trim($f, '"'), 
                                        explode(' ', trim($fieldsList, '()')));

        $signatureComponents = [];

        foreach ($coveredFields as $field) {
            $signatureComponents[] = $this->canonicalizeComponent($field, $headers, 
                                                                        $method, $path);
        }

        $signatureParamsStr = "($fieldsList)";
        foreach ($params as $k => $v) {
            $v = is_string($v) ? '"'.$v.'"' : $v;
            $signatureParamsStr .= ";$k=$v";
        }

        $signatureComponents[] = '"@signature-params": '.$signatureParamsStr;
        $signatureBase = implode("\n", $signatureComponents);
        $decodedSig = base64_decode($sigDict['sig1']);

        return $this->verifySignature($signatureBase, $decodedSig, $params['alg'] ?? $this->alg);
    }

    private function canonicalizeComponent(string $field, array $headers, 
                                            string $method, string $path): string
    {
        return match ($field) {
            '@method' => '"@method": ' . strtolower($method),
            '@path' => '"@path": '.$path,
            default => '"'.$field.'": '.$this->normalizeHeader($headers[$field] ?? ''),
        };
    }

    private function normalizeHeader(string $value): string
    {
        return trim(preg_replace('/\s+/', ' ', $value));
    }

    private function createSignature(string $data): string
    {
        return match ($this->alg) {
            'rsa-sha256' => $this->rsaSign($data),
            'ed25519' => $this->ed25519Sign($data),
            'hmac-sha256' => base64_encode(hash_hmac('sha256', $data, $this->privateKey, true)),
            default => throw new \RuntimeException("Unsupported algorithm: $this->alg")
        };
    }

    private function verifySignature(string $data, string $signature, string $alg): bool
    {
        return match ($alg) {
            'rsa-sha256' => openssl_verify($data, $signature, $this->publicKey, 
                                                OPENSSL_ALGO_SHA256) === 1,
            'ed25519' => openssl_verify($data, $signature, $this->publicKey, "Ed25519") === 1,
            'hmac-sha256' => hash_equals(
                base64_encode(hash_hmac('sha256', $data, $this->privateKey, true)),
                base64_encode($signature)
            ),
            default => false
        };
    }

    /* sign with rsa or ed25519 */

    private function rsaSign(string $data): string
    {
        if (!openssl_sign($data, $signature, $this->privateKey, OPENSSL_ALGO_SHA256)) {
            throw new \RuntimeException("RSA signing failed");
        }
        return base64_encode($signature);
    }

    private function ed25519Sign(string $data): string
    {
        if (!openssl_sign($data, $signature, $this->privateKey, "Ed25519")) {
            throw new \RuntimeException("Ed25519 signing failed");
        }
        return base64_encode($signature);
    }

    /* parse a structed dict */

    private function parseStructuredDict(string $headerValue): array
    {
        $result = [];
        $parts = explode(',', $headerValue);
        foreach ($parts as $part) {
            if (preg_match('/\s*(\w+)=\(([^)]*)\)((;.*)*)/', $part, $matches)) {
                $label = trim($matches[1]);
                $fields = $matches[2];
                $paramStr = trim($matches[3] ?? '');
                $params = [];

                if ($paramStr) {
                    preg_match_all('/;([^=]+)=(".*?"|\d+|\w+)/', $paramStr, 
                                        $paramMatches, PREG_SET_ORDER);
                    foreach ($paramMatches as $pm) {
                        $k = $pm[1];
                        $v = $pm[2];
                        $params[$k] = str_starts_with($v, '"') ? trim($v, '"') : $v;
                    }
                }

                $result[$label] = [$fields, $params];
            } elseif (preg_match('/\s*(\w+)=:([^:]+):/', $part, $matches)) {
                $result[trim($matches[1])] = $matches[2];
            }
        }
        return $result;
    }

    /* Recommended to calculate the digest of the body and add it to 
        covered headers and sign, but not required. Covenience function 
        to calculate the digest.. 

        ex:

        $digest = $signer->createContentDigestHeader($body);
        $request = $request->withHeader('Content-Digest', $digest);
    */

    public function createContentDigestHeader(string $body): string
    {
        $digest = hash('sha256', $body, true);
        return 'sha-256=:'.base64_encode($digest).':';
    }

    /* Convenience function, probably want to use a robust PSR7 solution instead */

    public static function parseHttpMessage(string $raw): array
    {
        [$headerPart, $body] = explode("\r\n\r\n", $raw, 2);
        $lines = explode("\r\n", $headerPart);
        $requestLine = array_shift($lines);
        [$method, $path] = explode(' ', $requestLine);

        $headers = [];
        foreach ($lines as $line) {
            [$name, $value] = explode(':', $line, 2);
            $headers[strtolower(trim($name))] = trim($value);
        }

        return [
            'method' => $method,
            'path' => $path,
            'headers' => $headers,
            'body' => $body
        ];
    }
}

