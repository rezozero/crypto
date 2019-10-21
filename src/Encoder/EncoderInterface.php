<?php
declare(strict_types=1);

namespace RZ\Crypto\Encoder;

use ParagonIE\Halite\Key;
use ParagonIE\HiddenString\HiddenString;

interface EncoderInterface
{
    public function encode(HiddenString $toEncode, Key $key): string;
    public function decode(string $encoded, Key $key): HiddenString;
}
