<?php

declare(strict_types=1);

namespace RZ\Crypto\KeyChain;

use ParagonIE\Halite\Key;

interface KeyChainInterface
{
    public function get(string $keyName): Key;
    public function save(Key $key, string $keyName): void;
    public function generate(string $keyName): Key;
}
