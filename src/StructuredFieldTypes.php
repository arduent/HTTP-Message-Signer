<?php
namespace HttpSignature;


class StructuredFieldTypes
{
    public function __construct()
    {
        return $this;
    }

    public function getFields(): array
    {
        $array = explode("\n", $this->fieldlist);
        foreach ($array as $key => $value) {
            $array[$key] = trim($value);
        }
        return $array;
    }

    public $fieldlist =
'accept list
accept-encoding list
accept-language list
accept-patch list
accept-post list
accept-ranges list
access-control-allow-credentials item
access-control-allow-headers list
access-control-allow-methods list
access-control-allow-origin item
access-control-expose-headers list
access-control-max-age item
access-control-request-headers list
access-control-request-method item
age item
allow list
alpn list
alt-svc dictionary
alt-used item
cache-control dictionary
cdn-loop list
clear-site-data list
connection list
content-encoding list
content-language list
content-length list
content-type item
cross-origin-resource-policy item
dnt item
expect dictionary
expect-ct dictionary
host item
keep-alive dictionary
max-forwards item
origin item
pragma dictionary
prefer dictionary
preference-applied dictionary
retry-after item
sec-websocket-extensions list
sec-websocket-protocol list
sec-websocket-version item
server-timing list
surrogate-control dictionary
te list
timing-allow-origin list
trailer list
transfer-encoding list
upgrade-insecure-requests item
vary list
x-content-type-options item
x-frame-options item
x-xss-protection list';

}