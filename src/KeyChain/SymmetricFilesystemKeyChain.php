<?php

declare(strict_types=1);

namespace RZ\Crypto\KeyChain;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Alerts\FileError;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\KeyFactory;

/**
 * One plain clear file per key.
 *
 * @package RZ\Crypto\Key
 */
class SymmetricFilesystemKeyChain extends AbstractFilesystemKeyChain
{
    /**
     * @param string $keyName
     *
     * @return Key
     * @throws FileError
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function generate(string $keyName): Key
    {
        try {
            $encKey = $this->get($keyName);
        } catch (CannotPerformOperation $e) {
            $encKey = KeyFactory::generateEncryptionKey();
            $this->save($encKey, $keyName);
        }
        return $encKey;
    }

    /**
     * @param string $keyName
     *
     * @return Key
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function get(string $keyName): Key
    {
        return KeyFactory::loadEncryptionKey($this->getKeyPath($keyName));
    }

    /**
     * @param Key    $key
     * @param string $keyName
     *
     * @throws FileError
     */
    public function save(Key $key, string $keyName): void
    {
        $file = $this->getKeyPath($keyName);
        if (file_exists($file)) {
            throw new FileError('File ' . $file . ' already exists.');
        }
        KeyFactory::save($key, $this->getKeyPath($keyName));
    }
}
