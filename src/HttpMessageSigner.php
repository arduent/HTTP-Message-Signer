<?php

namespace HttpSignature;

use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;
use Bakame\Http\StructuredFields\Dictionary;

class HttpMessageSigner
{
    private string $keyId;
    private string $privateKey;
    private string $publicKey;
    private string $algorithm;

    protected $request;
    protected $response;


    public function __construct(RequestInterface $request, ResponseInterface $response) {
        $this->request = $request;
        $this->response = $response;
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

    /* PSR-7 interface to signing function */

    public function signRequest(array $coveredFields): RequestInterface
    {
        $headers = [];
        foreach ($this->request->getHeaders() as $name => $values) {
            $headers[strtolower($name)] = implode(', ', $values);
        }

        $signedHeaders = $this->sign(
            $headers,
            $coveredFields
        );

        foreach (['signature-input', 'signature'] as $header) {
            $request = $this->request->withHeader($header, $signedHeaders[$header]);
            $this->setRequest($request);
        }

        return $request;
    }

    /* PSR-7 verify interface and also check body digest if included */

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
        if (! in_array($matches[1], ['256', '512'], true)) {
            return false;
        }

        $algorithm = 'sha' . $matches[1];

        $expectedDigest = base64_decode($matches[2]);
        $actualDigest = hash($algorithm, $body, true);

        return hash_equals($expectedDigest, $actualDigest);
    }

    /* non-PSR-7 sign function, header names are made lowercase */

    public function sign(array $headers, array $coveredFields): array
    {
        $coveredFields = array_map('strtolower', $coveredFields);
        $signatureComponents = [];

        foreach ($coveredFields as $field) {
            $signatureComponents[] = $this->canonicalizeComponent($field, $headers);
        }

        $paramList = implode(' ', array_map(fn($f) => '"' . $f . '"', $coveredFields));
        $signatureInput = '(' . $paramList . ');keyid="'
                . $this->keyId . '";alg="' . $this->algorithm . '"';

        /**
         * Always include @signature-params in the result.
         */
        $signatureComponents[] = '"@signature-params": ' . $signatureInput;

        $signatureBase = implode("\n", $signatureComponents);
        $signature = $this->createSignature($signatureBase);

        $headers['signature-input'] = "sig1=$signatureInput";
        $headers['signature'] = "sig1=:$signature:";

        return $headers;
    }

    public function verify(array $headers): bool
    {
        if (!isset($headers['signature-input'], $headers['signature'])) {
            return false;
        }
        $headers[] = 'signature-params';

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
            $signatureComponents[] = $this->canonicalizeComponent($field, $headers);
        }

        $signatureParamsStr = "($fieldsList)";
        foreach ($params as $k => $v) {
            $v = is_string($v) ? '"'.$v.'"' : $v;
            $signatureParamsStr .= ";$k=$v";
        }

        $signatureComponents[] = '"@signature-params": '.$signatureParamsStr;
        $signatureBase = implode("\n", $signatureComponents);
        $decodedSig = base64_decode($sigDict['sig1']);

        return $this->verifySignature($signatureBase, $decodedSig, $params['alg'] ?? $this->algorithm);
    }

    private function canonicalizeComponent(string $field, array $headers): string
    {
        $parsedField = explode(';', $field);
        $fieldName = $parsedField[0];
        $fieldParams = $parsedField[1] ?? [];

        $fieldValue = match ($fieldName) {
            '@signature-params' => '',
            '@method' => '"@method": ' . strtoupper($this->request->getMethod()),
            '@authority' => '"@authority": ' . $this->request->getUri()->getAuthority(),
            '@scheme' => '"@scheme": ' . strtoupper($this->request->getUri()->getScheme()),
            '@target-uri' => '"@target-uri": ' . $this->request->getUri(), // ?? verify
            '@request-target' => '"@request-target": ' . $this->request->getUri(), // ?? verify
            '@path' => '"@path": ' . $this->request->getUri()->getPath(),
            '@query' => '"@query": ' . $this->request->getUri()->getQuery(),
            '@query-param' => $this->getQueryParam($fieldParams) ?? '',
            '@status' => '"@status": ' . $this->response->getStatusCode(),
            default => '"' . $field . '": ' . $this->normalizeHeader($headers[$field] ?? ''),
        };
        return $fieldValue;
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
     * @param $params
     * @param $name
     * @return string|null
     *
     * Find one query parameter by name (which must supplied as parameters in the (structured) covered field list).
     */
    private function getQueryParam($params, $name = 'name'): string|null
    {
        $queryString = $this->request->getUri()->getQuery();
        $queryParams = [];
        if ($queryString) {
            $queryParams = $this->parseQueryString($queryString);
            if (is_array($params)) {
                foreach ($params as $param => $value) {
                    if ($param === $name) {
                        return $value;
                    }
                }
            }
            if (is_string($params)) {
                
            }
        }
        return null;
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

    private function parseStructuredDict(string $headerValue): array
    {

        /**
         * Work in progress. This first section is an attempt to replace the following
         * manual parser with a structured parser built on bakame/http-structured-fields
         */

        $parsed = Dictionary::fromHttpValue($headerValue);
        $parsedString = $parsed->__toString();
        $parsedArray = $parsed->toAssociative();
        foreach ($parsedArray as $key => $value) {
            $k = $key;
            $v = $value;
        }

        /**
         * Original manual parser
         */
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

