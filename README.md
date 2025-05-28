# HTTP Message Signer (RFC 9421)


A PHP 8.1+ library for signing and verifying HTTP messages (requests or responses) per [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421).

Supports:
- RSA-SHA256
- Ed25519
- HMAC-SHA256
- PSR-7 requests (e.g., Guzzle)
- Optionally (recommended) calculate and verify body digest (content-digest header)

Requirements:
- bakame/http-structured-fields
- psr/http-message

## Note

This is Alpha version please report issues. Thanks. Tested on PHP 8.4, should run fine on 8.1+

2025-05-28: Partially reversed the constructor change. 


## Installation

```bash
composer require quantificant/http-message-signer
```


## Notes

An instance of a PSR-7 MessageInterface is passed to the sign and verify functions. This can be a RequestInterface or a ResponseInterface. Typically, this will be a RequestInterface. Most frameworks provide a PSR-7 Request/Response interface pair which are connected to your web server application using $request->fromGlobals() or something similar. This would typically be used to verify a message. 

To sign a message, install the composer package guzzlehttp/psr7 and create an instance of `Request`.

## Usage

```php
use HttpSignature\HttpMessageSigner;
use GuzzleHttp\Psr7\Request;

$request = new Request(
    'GET',
    'https://api.example.com/resource?bat&baz=3',
    [
        'Host' => ['api.example.com'],
        'Date' => [gmdate('D, d M Y H:i:s T')],
    ]
);

$signer = (new HttpMessageSigner())
    ->setPrivateKey($privateKey)
    ->setPublicKey($publicKey)
    ->setKeyId('test-key')
    ->setAlgorithm('rsa-sha256');

$request = $signer->signRequest('("@method" "@path" "host" "date")', $request);
$isValid = $signer->verifyRequest($request);
```

See full examples in `/tests`.

## Structured Fields

RFC9421 makes heavy use of HTTP Structured Fields (RFC8941/RFC9651). The syntax is very precise and unforgiving.

The signRequest() method takes a structured InnerList of components to sign. These may be headers or derived fields. 

Using the 'sf' parameter on a component will treat it as a Structured Field when normalising the string. 

However, parsing Structured Fields is likely to fail unless you know what `type` it is. This library has no current knowledge of all the header fields which could potentially be structured. So there are two methods available -- setStructuredFieldTypes() and addStructuredFieldTypes(). These take an array with key of the lowercase header name and a value which is one of 'list', 'innerlist', 'parameters, 'dictionary', 'item'. If the header name is in the list and the 'sf' modifier is used, the header will be parsed as the Structured Field type indicated.  


The signRequest() and verifyRequest() methods both use an instance of MessageInterface. In nearly all cases, this will be the RequestInterface. When signing responses, the default will be the ResponseInterface, and if components are required from the RequestInterface, the :req parameter must be added to the field definition. 

To sign or verify a Response, use a ResponseInterface as the `$interface`, and provide the RequestInterface in `$originalRequest`. This will allow the `req` modifier to work correctly.





## License

BSD 3-Clause
