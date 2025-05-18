# HTTP Message Signer (RFC 9421)

This is a fork of quantificant/http-message-signer ( https://github.com/arduent/HTTP-Message-Signer ).

It is currently a work in progress and possibly unstable (19-May-2025). What we're doing is extending the original work to more fully cover the expected behaviours of the base specification, as there are very few implementations of RFC9421 in php and as far as I'm aware at the moment, they are all woefully incomplete. The first step was to use a complete and tested structured HTTP header parser and require a PSR-7 request interface (which was optional in the original implementation). Then I've started supporting the full range of '@' derived components, and the associated named parameters which were also lacking. 

If you would like to help with this effort, a fediverse group will be created in the next several days and the location will be provided here. 


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

## Installation

```bash
composer require quantificant/http-message-signer
```

## Usage

```php
use HttpSignature\HttpMessageSigner;

$signer = new HttpMessageSigner(...);
$request = $signer->signRequest($psrRequest, ['@method', '@path', 'host']);
```

See full examples in `/tests`.

## License

BSD 3-Clause
