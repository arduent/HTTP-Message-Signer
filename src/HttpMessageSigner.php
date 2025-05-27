<?php

namespace HttpSignature;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\Parameters;
use Psr\Http\Message\MessageInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Bakame\Http\StructuredFields\Dictionary;

class HttpMessageSigner
{
    private string $keyId;
    private string $privateKey;
    private string $publicKey;
    private string $algorithm;
    private string $signatureId = 'sig1';

    protected $request;
    protected $response;
    protected $interface;


    public function __construct(RequestInterface $request, ResponseInterface $response = null)
    {
        $this->request = $request;
        $this->response = $response;
        $this->interface = $request;
        return $this;
    }

    /**
     * @return RequestInterface
     */
    public function getRequest(): RequestInterface
    {
        return $this->request;
    }

    /**
     * @param RequestInterface $request
     * @return HttpMessageSigner
     */
    public function setRequest(RequestInterface $request): HttpMessageSigner
    {
        $this->request = $request;
        return $this;
    }

    /**
     * @return ResponseInterface
     */
    public function getResponse(): ResponseInterface
    {
        return $this->response;
    }

    /**
     * @param ResponseInterface $response
     * @return HttpMessageSigner
     */
    public function setResponse(ResponseInterface $response): HttpMessageSigner
    {
        $this->response = $response;
        return $this;
    }

    /**
     * This sets which of [$request, $response] is the signing interface
     * By default it is $request.
     *
     * @param MessageInterface $interface
     * @return $this
     */
    public function setInterface(MessageInterface $interface): HttpMessageSigner
    {
        $this->interface = $interface;
        return $this;
    }

    public function getInterface(): MessageInterface
    {
        return $this->interface;
    }


    /**
     * @return string
     */
    public function getKeyId(): string
    {
        return $this->keyId;
    }

    /**
     * @param string $keyId
     * @return HttpMessageSigner
     */
    public function setKeyId(string $keyId): HttpMessageSigner
    {
        $this->keyId = $keyId;
        return $this;
    }

    /**
     * @return string
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    /**
     * @param string $privateKey
     * @return HttpMessageSigner
     */
    public function setPrivateKey(string $privateKey): HttpMessageSigner
    {
        $this->privateKey = $privateKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * @param string $publicKey
     * @return HttpMessageSigner
     */
    public function setPublicKey(string $publicKey): HttpMessageSigner
    {
        $this->publicKey = $publicKey;
        return $this;
    }

    /**
     * @return string
     */
    public function getAlgorithm(): string
    {
        return $this->algorithm;
    }

    /**
     * @param string $algorithm
     * @return HttpMessageSigner
     */
    public function setAlgorithm(string $algorithm): HttpMessageSigner
    {
        $this->algorithm = $algorithm;
        return $this;
    }

    /**
     * @return string
     */
    public function getSignatureId(): string
    {
        return $this->signatureId;
    }

    /**
     * @param string $signatureId
     * @return HttpMessageSigner
     */
    public function setSignatureId(string $signatureId): HttpMessageSigner
    {
        $this->signatureId = $signatureId;
        return $this;
    }

    public function getHeaders(): array
    {
        $headers = [];
        foreach ($this->request->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }
        return $headers;
    }


    /* PSR-7 interface to signing function */

    public function signRequest(string $coveredFields, $interface = null): MessageInterface
    {
        $headers = $this->getHeaders();
        if ($interface !== null) {
            $this->setInterface($interface);
        }


        $signedHeaders = $this->sign(
            $headers,
            $coveredFields
        );

        foreach (['signature-input', 'signature'] as $header) {
            $interface = $interface->withHeader($header, $signedHeaders[$header]);
            $this->setRequest($interface);
        }

        return $interface;
    }

    /* PSR-7 verify interface and also check body digest if included */

    public function verifyRequest(MessageInterface $interface): bool
    {
        $headers = [];
        foreach ($interface->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        /* check the body digest if it's present */

        if (isset($headers['content-digest'])) {
            $body = (string)$interface->getBody();
            if (!$this->isBodyDigestValid($body, $headers['content-digest'])) {
                return false;
            }
        }

        return $this->verify($headers);
    }

    /**
     * check body digest
     *
     * From https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Digest
     * The algorithm used to create a digest of the message content. Only two registered digest algorithms are
     * considered secure: sha-512 and sha-256. The insecure (legacy) registered digest algorithms
     * are: md5, sha (SHA-1), unixsum, unixcksum, adler (ADLER32) and crc32c.
     */

    private function isBodyDigestValid(string $body, string $headerValue): bool
    {
        if (!preg_match('/sha-(.*?)=:(.*?):/', $headerValue, $matches)) {
            return false;
        }
        if (!in_array($matches[1], ['256', '512'], true)) {
            return false;
        }

        $algorithm = 'sha' . $matches[1];

        $expectedDigest = base64_decode($matches[2]);
        $actualDigest = hash($algorithm, $body, true);

        return hash_equals($expectedDigest, $actualDigest);
    }

    /**
     * @param array $headers
     * @param string $coveredFields
     *
     * Can be used as a development function to peek into the internals of the exact things
     * that were signed and/or test the internal results of data normalisation.
     * This matches the sign() function except that it just returns the serialised string
     * and does not sign it.
     */
    public function calculateSignatureBase(array $headers, string $coveredFields)
    {
        $signatureComponents = [];
        $processedComponents = [];
        $dict = $this->parseStructuredDict($coveredFields);

        if ($dict->isNotEmpty()) {
            $coveredStructuredFields = $dict->__toString();
            $indices = $dict->indices();
            foreach ($indices as $index) {
                $member = $dict->getByIndex($index);
                if (!$member) {
                    throw new \Exception('Index ' . $index . ' not found');
                }
                if (in_array($member, $processedComponents, true)) {
                    throw new \Exception('Duplicate member found');
                }
                $processedComponents[] = $member;
                $signatureComponents[] = $this->canonicalizeComponent($member, $headers);
            }
        }

        $signatureInput = $coveredStructuredFields . ';keyid="'
            . $this->keyId . '";alg="' . $this->algorithm . '"';

        /**
         * Always include @signature-params in the result.
         */
        $signatureComponents[] = '"@signature-params": ' . $signatureInput;

        $signatureBase = implode("\n", $signatureComponents);
        return $signatureBase;

    }

    public function sign(array $headers, string $coveredFields): array
    {
        $signatureComponents = [];
        $processedComponents = [];

        $dict = $this->parseStructuredDict($coveredFields);

        if ($dict->isNotEmpty()) {
            $coveredStructuredFields = $dict->__toString();
            $indices = $dict->indices();
            foreach ($indices as $index) {
                $member = $dict->getByIndex($index);
                if (!$member) {
                    throw new \Exception('Index ' . $index . ' not found');
                }
                if (in_array($member, $processedComponents, true)) {
                    throw new \Exception('Duplicate member found');
                }
                $processedComponents[] = $member;
                $signatureComponents[] = $this->canonicalizeComponent($member, $headers);
            }
        }

        $signatureInput = $coveredStructuredFields . ';keyid="'
                . $this->keyId . '";alg="' . $this->algorithm . '"';

        /**
         * Always include @signature-params in the result.
         */
        $signatureComponents[] = '"@signature-params": ' . $signatureInput;

        $signatureBase = implode("\n", $signatureComponents);

        $signature = $this->createSignature($signatureBase);

        $headers['signature-input'] = "$this->signatureId=$signatureInput";
        $headers['signature'] = "$this->signatureId=:$signature:";

        return $headers;
    }

    public function verify(array $headers): bool
    {
        if (!isset($headers['signature-input'], $headers['signature'])) {
            return false;
        }
        $headers[] = 'signature-params';

        $sigInputDict = $this->parseStructuredDict($headers['signature-input']);

        $signatureComponents = [];

        if ($sigInputDict->isNotEmpty()) {
            $coveredStructuredFields = $sigInputDict->__toString();
            $indices = $sigInputDict->indices();
            foreach ($indices as $index) {
                [$dictName, $members] = $sigInputDict->getByIndex($index);
                if ($members instanceof InnerList) {
                    $innerIndices = $members->indices();
                    foreach ($innerIndices as $innerIndex) {
                       $member = $members->getByIndex($innerIndex);
                       $signatureComponents[$dictName][] = $this->canonicalizeComponent($member, $headers);
                    }
                }
            }
        }

        $sigDict = $this->parseStructuredDict($headers['signature']);
        if ($sigDict->isNotEmpty()) {
            $coveredStructuredFields = $sigInputDict->__toString();
            $indices = $sigDict->indices();
            foreach ($indices as $index) {
                [$dictName, $members] = $sigDict->getByIndex($index);
                if ($members instanceof Item) {
                    $signatures[$dictName] = $members->value();
                }
                if ($members instanceof InnerList) {
                    $innerIndices = $members->indices();
                    foreach ($innerIndices as $innerIndex) {
                        $signatures[$dictName][] = $members->getByIndex($innerIndex);
                    }
                }
            }
        }

        foreach ($signatureComponents as $dictName => $dictComponents) {
            $namedSignatureComponents = $signatureComponents[$dictName];
            $signatureParamsStr = $sigInputDict[$dictName]->toHttpValue();
            $namedSignatureComponents[] = '"@signature-params": ' . $signatureParamsStr;
            $signatureBase = implode("\n", $namedSignatureComponents);
            if (!isset($sigDict[$dictName])) {
                return false;
            }

            $decodedSig = base64_decode($sigDict[$dictName]);

            return $this->verifySignature($signatureBase, $decodedSig, $params['alg'] ?? $this->algorithm);
        }
        return false;
    }

    protected function extractParameters($field): array
    {
        $parameters = [];
        $fieldParams = $field->parameters();

        if ($fieldParams->isNotEmpty()) {
            $indices = $fieldParams->indices();
            foreach ($indices as $index) {
                [$name, $item] = $fieldParams->getByIndex($index);
                $parameters[$name] = $item->value();
            }
        }
        return $parameters;
    }

    private function canonicalizeComponent($field, array $headers): string
    {
        $fieldName = $field->value();
        $parameters = $this->extractParameters($field);
        if (isset($parameters['bs']) && isset($parameters['sf'])) {
            throw new \Exception('Cannot use both bs and sf');
        }

        $whichRequest = $this->getInterface();
        if (isset($parameters['req'])) {
            if ($whichRequest === $this->getRequest()) {
                throw new \Exception(':req parameter used for request interface');
            }
            $whichRequest = $this->getRequest();
        }
        $whichHeaders = $headers;
        if (isset($parameters['tr'])) {
            // Do nothing currently. PSR-7 includes trailers in the headers.
            // @todo: We should check that they are listed in the Trailers header.
            $whichHeaders = $headers;
        }
        [$name, $value] = $this->getFieldValue($fieldName, $whichRequest, $whichHeaders, $parameters);
        if ($parameters['sf']) {
            $value = $this->applyStructuredField($value);
        }
        return $name . ': ' . $value;
    }

    private function getFieldValue($fieldName, $whichRequest, $headers, $parameters): array
    {
        $value = match ($fieldName) {
            '@signature-params' => ['', ''],
            '@method' => ['"@method"', strtoupper($whichRequest->getMethod())],
            '@authority' => ['"@authority"', $whichRequest->getUri()->getAuthority()],
            '@scheme' => ['"@scheme"', strtolower($whichRequest->getUri()->getScheme())],
            '@target-uri' => ['"target-uri"', $whichRequest->getUri()->__toString()],
            '@request-target' => ['"@request-target"', $whichRequest->getRequestTarget()],
            '@path' => ['"@path"', $whichRequest->getUri()->getPath()],
            '@query' => ['"@query"', $whichRequest->getUri()->getQuery()],
            '@query-param' => $this->getQueryParam($whichRequest, $parameters) ?? ['', ''],
            '@status' => ['"@status"', '"@status": ' . $whichRequest->getStatusCode()],
            default => ['"' . $fieldName . '"', $this->normalizeHeader($headers[$fieldName] ?? '')],
        };
        return $value;
    }

    /**
     * @param string $query
     * @return array|null
     *
     * Should not use PHP's parse_str function here, as it has some issues with
     * spaces and dots in parameter names. These are unlikely to occur, but the
     * following function treats them as opaque strings rather than as variable
     * names.
     */
    private function parseQueryString(string $query): array|null
    {
        $result = [];

        if (!isset($query)) {
            return null;
        }

        $queryParams = explode('&', $query);
        foreach ($queryParams as $param) {
            // The '=' character is not required and indicates a boolean true value if unset.
            $element = explode('=', $param, 2);
            $result[urldecode($element[0])] = isset($element[1]) ? urldecode($element[1]) : '';
        }
        return $result;
    }

    /**
     * @param $parameters
     * @param $name
     * @return string|null
     *
     * Find one query parameter by name (which must supplied as parameters in the (structured) covered field list).
     */
    private function getQueryParam($whichRequest, array $parameters): array
    {
        $queryString = $whichRequest->getUri()->getQuery();
        if ($queryString) {
            $queryParams = $this->parseQueryString($queryString);
            $fieldName = $parameters['name'];
            if ($fieldName) {
                return ['"_' . $fieldName . '_"', '"' . ($queryParams[$fieldName] ?? '') . '"'];
            }
        }
        throw new \Exception('Query string named parameter not set');
    }

    private function applyRule(string $fieldValue, string $param): string
    {
        return match ($param) {
            'sf' => $this->applyStructuredField($fieldValue),
            'key' => $this->applySingleKeyValue($fieldValue),
            'bs' => $this->applyByteSequence($fieldValue),
            'tr' => $this->applyTrailer($fieldValue),
            'req' => $this->applyRelatedRequest($fieldValue),
            'name' => $this->applySingleNamedQueryParameter($fieldValue),
            default => $fieldValue,
        };
    }

    private function applyStructuredField(string $fieldValue): string
    {
        $field = Dictionary::fromHttpValue($fieldValue);
        return $field->toHttpValue();
    }

    private function applySingleKeyValue(string $fieldValue): string
    {
        return $fieldValue;
    }

    private function applyByteSequence(string $fieldValue): string
    {
        return $fieldValue;
    }

    private function applyTrailer(string $fieldValue): string
    {
        return $fieldValue;
    }
    private function applyRelatedRequest(string $fieldValue): string
    {
        return $fieldValue;
    }
    private function applySingleNamedQueryParameter(string $fieldValue): string
    {
        return $fieldValue;
    }


    private function normalizeHeader(string $value): string
    {
        return trim(preg_replace('/\s+/', ' ', $value));
    }

    private function createSignature(string $data): string
    {
        return match ($this->algorithm) {
            'rsa-sha256' => $this->rsaSign($data),
            'ed25519' => $this->ed25519Sign($data),
            'hmac-sha256' => base64_encode(hash_hmac('sha256', $data, $this->privateKey, true)),
            default => throw new \RuntimeException("Unsupported algorithm: $this->algorithm")
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

    private function parseStructuredDict(string $headerValue)
    {
        /**
         * Work in progress. This first section is an attempt to replace the following
         * manual parser with a structured parser built on bakame/http-structured-fields
         */
        if (str_starts_with(trim($headerValue), '(')) {
            return InnerList::fromHttpValue($headerValue);
        }
        else {
            return Dictionary::fromHttpValue($headerValue);
        }
    }

    /* Recommended to calculate the digest of the body and add it to 
        covered headers and sign, but not required. Convenience function
        to calculate the digest.

        ex:

        $digest = $signer->createContentDigestHeader($body);
        $request = $request->withHeader('Content-Digest', $digest);
    */

    /**
     * @param string $body
     * @param $algorithm ('sha256' || 'sha512')
     * @return string
     *
     * From https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Digest
     * The algorithm used to create a digest of the message content. Only two registered digest algorithms are
     * considered secure: sha-512 and sha-256. The insecure (legacy) registered digest algorithms
     * are: md5, sha (SHA-1), unixsum, unixcksum, adler (ADLER32) and crc32c.
     */

    public function createContentDigestHeader(string $body, $algorithm = 'sha256'): string
    {
        $supportedAlgorithms = ['sha256' => 'sha-256', 'sha512' => 'sha-512'];
        foreach ($supportedAlgorithms as $alg => $value) {
            if ($alg === $algorithm) {
                $algorithmHeaderString = $value;
                break;
            }
        }
        if (!isset($algorithmHeaderString)) {
            throw new \RuntimeException("Unsupported algorithm: $algorithm");
        }
        $digest = hash($algorithm, $body, true);
        /**
         * Output as structured field.
         */
        return $algorithmHeaderString . '=:' . base64_encode($digest) . ':';
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

