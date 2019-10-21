<?php
declare(strict_types=1);

namespace RZ\Crypto\Encoder;

use ParagonIE\HiddenString\HiddenString;

/**
 * Just pass clear string, do not encode or decode nothing.
 *
 * @package RZ\Crypto\Encoder
 */
class ByPassUniqueKeyEncoder implements UniqueKeyEncoderInterface
{
    public function encode(HiddenString $toEncode): string
    {
        return $toEncode->getString();
    }

    public function decode(string $encoded): HiddenString
    {
        return new HiddenString($encoded);
    }
}
