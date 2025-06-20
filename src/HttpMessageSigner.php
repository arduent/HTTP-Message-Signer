<?php

namespace HttpSignature;

use Bakame\Http\StructuredFields\InnerList;
use Bakame\Http\StructuredFields\Item;
use Bakame\Http\StructuredFields\OuterList;
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
    private string $created = '';
    private string $expires = '';
    private string $nonce = '';
    private string $tag = '';

    private array $structuredFieldTypes = [];

    private $originalRequest;


    public function __construct()
    {
        $this->setStructuredFieldTypes((new StructuredFieldTypes())->getFields());
        return $this;
    }

    public function getHeaders($interface): array
    {
        $headers = [];
        foreach ($interface->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }
        return $headers;
    }


    /* PSR-7 interface to signing function */

    public function signRequest(string $coveredFields, MessageInterface $interface, RequestInterface $originalRequest = null): MessageInterface
    {
        $headers = $this->getHeaders($interface);
        if ($originalRequest) {
            $this->setOriginalRequest($originalRequest);
        }

        $signedHeaders = $this->sign(
            $headers,
            $coveredFields,
            $interface
        );

        foreach (['signature-input', 'signature'] as $header) {
            $interface = $interface->withHeader($header, $signedHeaders[$header]);
        }
        return $interface;
    }

    /* PSR-7 verify interface and also check body digest if included */

    public function verifyRequest(MessageInterface $interface, RequestInterface $originalRequest = null): bool
    {
        $headers = [];
        if ($originalRequest) {
            $this->setOriginalRequest($originalRequest);
        }
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

        return $this->verify($headers, $interface);
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
    public function calculateSignatureBase(array $headers, string $coveredFields, $interface)
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
                $signatureComponents[] = $this->canonicalizeComponent($member, $headers, $interface);
            }
        }

        $signatureInput = $coveredStructuredFields . ';keyid="'
            . $this->keyId . '";alg="' . $this->algorithm . '"';

        if ($this->created) {
            $signatureInput .= ';created=' . $this->created;
        }
        if ($this->expires) {
            $signatureInput .= ';expires=' . $this->expires;
        }
        if ($this->nonce) {
            $signatureInput .= ';nonce="' . $this->nonce . '"';
        }
        if ($this->tag) {
            $signatureInput .= ';tag="' . $this->tag . '"';
        }


        /**
         * Always include @signature-params in the result.
         */
        $signatureComponents[] = '"@signature-params": ' . $signatureInput;

        $signatureBase = implode("\n", $signatureComponents);
        return $signatureBase;

    }

    public function sign(array $headers, string $coveredFields, MessageInterface $interface): array
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
                $signatureComponents[] = $this->canonicalizeComponent($member, $headers, $interface);
            }
        }

        $signatureInput = $coveredStructuredFields . ';keyid="'
                . $this->keyId . '";alg="' . $this->algorithm . '"'
                . (($this->created) ? ';created=' . $this->created : '')
                . (($this->expires) ? ';expires=' . $this->expires : '')
                . (($this->nonce) ? ';nonce="' . $this->nonce . '"' : '')
                . (($this->tag) ? ';tag="' . $this->tag . '"' : '');

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

    public function verify(array $headers, $interface): bool
    {
        if (!isset($headers['signature-input'], $headers['signature'])) {
            return false;
        }
        $headers[] = 'signature-params';

        $sigInputDict = $this->parseStructuredDict($headers['signature-input']);

        $signatureComponents = [];

        if ($sigInputDict->isNotEmpty()) {
            $indices = $sigInputDict->indices();
            foreach ($indices as $index) {
                [$dictName, $members] = $sigInputDict->getByIndex($index);
                if ($members instanceof InnerList) {
                    $innerIndices = $members->indices();
                    foreach ($innerIndices as $innerIndex) {
                       $member = $members->getByIndex($innerIndex);
                       $signatureComponents[$dictName][] = $this->canonicalizeComponent($member, $headers, $interface);
                    }
                    $parameters = $this->extractParameters($members);

                    if ($parameters['expires']) {
                        $expires = (int) $parameters['expires'];
                        if ($expires < time()) {
                            return false;
                        }
                        if ($parameters['created']) {
                            $created = (int) $parameters['created'];
                            if ($created >= $expires) {
                                return false;
                            }
                        }
                    }
                }
            }
        }

        $sigDict = $this->parseStructuredDict($headers['signature']);
        if ($sigDict->isNotEmpty()) {
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

            $decodedSig = base64_decode(trim($sigDict[$dictName]->__toString(), ':'));
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

    private function canonicalizeComponent($field, array $headers, MessageInterface $interface): string
    {
        $fieldName = $field->value();
        $parameters = $this->extractParameters($field);
        if (isset($parameters['bs']) && isset($parameters['sf'])) {
            throw new \Exception('Cannot use both bs and sf');
        }

        $whichRequest = $interface;
        if (isset($parameters['req']) && $interface instanceof ResponseInterface) {
            $whichRequest = $this->getOriginalRequest();
        }
        $whichHeaders = $headers;

        if (isset($parameters['tr'])) {
            $whichHeaders = $whichRequest->getTrailers();
        }

        [$name, $value] = $this->getFieldValue($fieldName, $whichRequest, $whichHeaders, $parameters);

        if (isset($parameters['bs'])) {
            $result = $name . ';bs: ';
            $values = $whichRequest->getHeader($fieldName);
            if (!$values) {
                return '';
            }
            if (!is_array($values)) {
                $values = [$values];
            }
            foreach ($values as $value) {
                $value = trim($value);
                $result .= ':' . base64_encode($value) . ':' . ', ';
            }
            return $values ? rtrim($result, ', ') : $result;
        }

        if (isset($parameters['sf'])) {
            $value = $this->applyStructuredField($name, $value);
            return $name . ';sf: ' . $value;
        }
        if (isset($parameters['key'])) {
            $childName = $parameters['key'];
            $value = $this->applySingleKeyValue($name, $childName, $value);
            return $name . ';key="' . $childName . '": ' . $value;
        }
        return $name . ': ' . $value;
    }

    private function getFieldValue($fieldName, MessageInterface $interface, $headers, $parameters ): array
    {
        $value = match ($fieldName) {
            '@signature-params' => ['', ''],
            '@method' => ['"@method"', strtoupper($interface->getMethod())],
            '@authority' => ['"@authority"', $interface->getUri()->getAuthority()],
            '@scheme' => ['"@scheme"', strtolower($interface->getUri()->getScheme())],
            '@target-uri' => ['"target-uri"', $interface->getUri()->__toString()],
            '@request-target' => ['"@request-target"', $interface->getRequestTarget()],
            '@path' => ['"@path"', $interface->getUri()->getPath()],
            '@query' => ['"@query"', $interface->getUri()->getQuery()],
            '@query-param' => $this->getQueryParam($interface, $parameters) ?? ['', ''],
            '@status' => ['"@status"', '"@status": ' . $interface->getStatusCode()],
            default => ['"' . $fieldName . '"', trim($headers[$fieldName] ?? '')],
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
                return ['"_' . $fieldName . '_"', $queryParams[$fieldName] ? '"' . $queryParams[$fieldName] . '"' : ''];
            }
        }
        throw new \Exception('Query string named parameter not set');
    }

    private function applyStructuredField(string $name, string $fieldValue): string
    {
        $type = $this->structuredFieldTypes[trim($name, '"')];
        switch ($type) {
            case 'list':
                $field = OuterList::fromHttpValue($fieldValue);
                break;
            case 'innerlist':
            $field = InnerList::fromHttpValue($fieldValue);
            break;
            case 'parameters':
            $field = Parameters::fromHttpValue($fieldValue);
            break;
            case 'dictionary':
                $field = Dictionary::fromHttpValue($fieldValue);
                break;
            case 'item':
                $field = Item::fromHttpValue($fieldValue);
                break;
            case 'url':
                return '"' . $fieldValue . '"';
            case 'date':
                return '@' . strtotime($fieldValue);
            case 'etag':
                $result = '';
                $list = explode(',', $fieldValue);
                foreach ($list as $item) {
                    if (str_starts_with(trim($item), 'W/')) {
                        $result .= substr(trim($item), 2) . '; w' . ', ';
                    } else {
                        $result .= trim($item) . ', ';
                    }
                }
                return rtrim($result, ', ');
            case 'cookie':
                // @TODO
            default:
                break;
        }
        if (!$field) {
            return '';
        }
        return $field->toHttpValue();
    }

    private function applySingleKeyValue(string $name, string $key, string $fieldValue): string
    {
        $type = $this->structuredFieldTypes[trim($name, '"')];
        if (empty($type) || $type === 'dictionary') {
            $dictionary = Dictionary::fromHttpValue($fieldValue);
            if ($dictionary->isNotEmpty() && isset($dictionary[$key])) {
                return $dictionary[$key]->toHttpValue();
            }
        }
        return '';
    }

    private function applyByteSequence(string $fieldValue): string
    {
        return $fieldValue;
    }

    private function applyTrailer(string $fieldValue): string
    {
        return $fieldValue;
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

    /**
     * @return array
     */
    public function getStructuredFieldTypes(): array
    {
        return $this->structuredFieldTypes;
    }

    /**
     * @param array $structuredFieldTypes
     * @return HttpMessageSigner
     */
    public function setStructuredFieldTypes(array $structuredFieldTypes): HttpMessageSigner
    {
        $this->structuredFieldTypes = $structuredFieldTypes;
        return $this;
    }

    /**
     * $structuredFieldType consists of a key named after a specific header field, and a value
     * which is one of 'list', 'innerlist', 'parameters, 'dictionary', 'item'.
     *
     * Example:
     *  ['example-dict' => 'dictionary']
     *
     * The 'sf' flag will not be honoured unless the structured type of the header is registered/known.
     *
     * @param array $structuredFieldType
     * @return $this
     */

    public function addStructuredFieldType(array $structuredFieldType): HttpMessageSigner
    {
        foreach ($structuredFieldType as $key => $value) {
            $this->structuredFieldTypes[$key] = $value;
        }
        return $this;
    }

    /**
     * @return mixed
     */
    public function getOriginalRequest()
    {
        return $this->originalRequest;
    }

    /**
     * @param mixed $originalRequest
     * @return HttpMessageSigner
     */
    public function setOriginalRequest($originalRequest)
    {
        $this->originalRequest = $originalRequest;
        return $this;
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

    /**
     * @return string
     */
    public function getCreated(): string
    {
        return $this->created;
    }

    /**
     * @param string $created
     * @return HttpMessageSigner
     */
    public function setCreated(string $created): HttpMessageSigner
    {
        $this->created = $created;
        return $this;
    }

    /**
     * @return string
     */
    public function getExpires(): string
    {
        return $this->expires;
    }

    /**
     * @param string $expires
     * @return HttpMessageSigner
     */
    public function setExpires(string $expires): HttpMessageSigner
    {
        $this->expires = $expires;
        return $this;
    }

    /**
     * @return string
     */
    public function getNonce(): string
    {
        return $this->nonce;
    }

    /**
     * @param string $nonce
     * @return HttpMessageSigner
     */
    public function setNonce(string $nonce): HttpMessageSigner
    {
        $this->nonce = $nonce;
        return $this;
    }

    /**
     * @return string
     */
    public function getTag(): string
    {
        return $this->tag;
    }

    /**
     * @param string $tag
     * @return HttpMessageSigner
     */
    public function setTag(string $tag): HttpMessageSigner
    {
        $this->tag = $tag;
        return $this;
    }
}

