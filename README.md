# HTTP Message Signer (RFC 9421)

This is a fork of quantificant/http-message-signer ( https://github.com/arduent/HTTP-Message-Signer ).

It is currently a work in progress and possibly unstable (19-May-2025). What we're doing is extending the original work to more fully cover the expected behaviours of the base specification, as there are very few implementations of RFC9421 in php and as far as I'm aware at the moment, they are all woefully incomplete. The first step was to use a complete and tested structured HTTP header parser and require a PSR-7 request interface (which was optional in the original implementation). Then I've started supporting the full range of '@' derived components, and the associated named parameters which were also lacking. 

If you would like to help with this effort, a fediverse group has been created at
https://fediversity.site/channel/rfc9421 (rfc9421@fediversity.site)

and a repository at https://codeberg.org/streams/http-sig9421

It would be awkward currently to link to this in composer, so what we're doing is test driven development. Write tests that fail and modify the code until they pass. Once we have a well established test suite covering the full suite of behaviour and everything is green, we'll create a pull request on quantificant/http-message-signer . 


A PHP 8.1+ library for signing and verifying HTTP messages (requests or responses) per [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421).

Supports:
- RSA-SHA256
- Ed25519
- HMAC-SHA256
- PSR-7 requests (e.g., Guzzle)
- Optionally (recommended) calculate and verify body digest (content-digest header)
- includes basic parser

## Note

This is Alpha version please report issues. Thanks. Tested on PHP 8.4, should run fine on 8.1+

Update to dev branch 2025-05-22: constructor has changed and "covered components" is now an HTTP structured InnerList (string) rather than an array of fields. You MUST provide a parseable/valid Innerlist element. RFC9421 is very opinionated, and signature failures are likely to be due to parsing incorrectly specified structured fields. You might want to wrap the sign and verify functionality in try/catch blocks and investigate all failures prior to releasing into production. 

## Installation

```bash
composer require quantificant/http-message-signer
```

## Usage

```php
use HttpSignature\HttpMessageSigner;

$request = new Request('GET', '/');
$response = new Response(200, ['Content-Type' => 'text/plain']);

$signer = (new HttpMessageSigner($request, $response))
    ->setPrivateKey($this->privateKey)
    ->setPublicKey($this->publicKey)
    ->setKeyId('test-key')
    ->setAlgorithm('rsa-sha256');

$request = $signer->signRequest($psrRequest, '("@method", "@path", "host")');
$isValid = $this->signer->verifyRequest($request);
```

See full examples in `/tests`.

## License

BSD 3-Clause
