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

An instance of a PSR-7 MessageInterface is passed to the sign and verify functions. This can be a RequestInterface or a ResponseInterface. Typically, this will be a RequestInterface. If your web framework does not supply a pre-populated PSR7-compatible request interface, you can quickly generate one using 

```
use GuzzleHttp\Psr7\ServerRequest;

$request = ServerRequest::fromGlobals();
```

This would typically be used to verify a message. 

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
        ...additional headers
    ]
);

$signer = (new HttpMessageSigner())
    ->setPrivateKey($privateKey) // only needed for signing
    ->setPublicKey($publicKey)   // only needed for verifying
    ->setKeyId('https://example.com/dave#rsaKey')  // required
    ->setAlgorithm('rsa-sha256')    // required
    ->setCreated(time())            // recommended
    ->setExpires(time() + 300)      // optional, contentious
    ->setNonce('xJJ9;ro.3*kidney`') // optional one-time token
    ->setTag('fediverse')           // optional app profile name
    ->setSignatureId('sig1')        // optional, default is sig1
    
    
$request = $signer->signRequest('("@method" "@path" "host" "date")', $request);
$isValid = $signer->verifyRequest($request);
```

See full examples in `/tests`.

## Structured Fields

RFC9421 makes heavy use of HTTP Structured Fields (RFC8941/RFC9651). The syntax is very precise and unforgiving.

The signRequest() method takes a structured InnerList of components to sign. These may be headers or derived fields.
The string will look something like the following (where `...` represents additional components):

```
'("header1" "header2" "@method" ...)'
```

and may include modifier parameters. These are represented as

```
'("@query-param";name="foo" "header2";sf "header3" ...)'
```

Parameters beginning with '@' are components derived from the HTTP request but may not be represented in the headers. Please review RFC9421 for precise definitions. 


Using the 'sf' parameter on a component will treat a signature component as a Structured Field when normalising the string. 

However, parsing Structured Fields by adding the 'sf' parameter is likely to fail unless you know what `type` it is. A built-in table contains the type definition for a number of known stuctured header types. This list is probably incomplete. A method `addStructuredFieldTypes()` is available to add the type information so it can be successfullly parsed. This takes an array with key of the lowercase header name and a value; which is one of 'list', 'innerlist', 'parameters, 'dictionary', 'item'. If the header name is in the list and the 'sf' modifier is used, the header will be parsed as the Structured Field type indicated.

If a Structured Field is declared as type 'dictionary'; it is suitable for use with the RFC9421 `key` parameter. Using this parameter will fail if the Structured Field type is unknown or has not been registered. 

The signRequest() and verifyRequest() methods both use an instance of MessageInterface. In nearly all cases, this will be the RequestInterface. However, when signing responses, the default will be the ResponseInterface, and if components are required from the RequestInterface, the :req parameter must be added to the field definition. 

To sign or verify an HTTP Response, use a ResponseInterface as the provided `$interface`, and provide the RequestInterface in `$originalRequest`. This is optional will allow the `req` modifier to work correctly when signing Responses.

## Known issues
Currently not implemented is the special handling of the `cookie` and `set-cookie` headers when using the `sf` modifier.

Also not currently implemented are some of the many signature algorithms; as we're currently focused primarily on rsa-sha256 and ed25519. 

Pull requests welcome. 


## License

BSD 3-Clause
