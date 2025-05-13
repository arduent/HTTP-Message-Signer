# HTTP Message Signer (RFC 9421)

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
