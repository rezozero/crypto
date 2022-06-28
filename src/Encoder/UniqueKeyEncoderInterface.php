<?php

declare(strict_types=1);

namespace RZ\Crypto\Encoder;

use ParagonIE\HiddenString\HiddenString;

interface UniqueKeyEncoderInterface
{
    public function encode(HiddenString $toEncode): string;
    public function decode(string $encoded): HiddenString;
}
