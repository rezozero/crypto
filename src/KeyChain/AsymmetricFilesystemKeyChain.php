<?php
declare(strict_types=1);

namespace RZ\Crypto\KeyChain;

use ParagonIE\Halite\Alerts\FileError;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\KeyFactory;

/**
 * One plain clear file per key.
 *
 * @package RZ\Crypto\Key
 */
class AsymmetricFilesystemKeyChain extends AbstractFilesystemKeyChain
{
    /**
     * @param string $keyName
     *
     * @return Key
     * @throws FileError
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function generate(string $keyName): Key
    {
        $keyPair = KeyFactory::generateEncryptionKeyPair();
        $this->save($keyPair->getSecretKey(), $keyName);
        $this->save($keyPair->getPublicKey(), $this->getPublicKeyName($keyName));
        return $keyPair->getSecretKey();
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
        return KeyFactory::loadEncryptionSecretKey($this->getKeyPath($keyName));
    }

    /**
     * @param string $keyName
     *
     * @return EncryptionPublicKey
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function getPublic(string $keyName): EncryptionPublicKey
    {
        return KeyFactory::loadEncryptionPublicKey($this->getKeyPath($this->getPublicKeyName($keyName)));
    }

    /**
     * Alias for get.
     *
     * @param string $keyName
     *
     * @return EncryptionSecretKey
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function getPrivate(string $keyName): EncryptionSecretKey
    {
        return $this->get($keyName);
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

    /**
     * @param string $keyName
     *
     * @return string
     */
    private function getPublicKeyName(string $keyName): string
    {
        return $keyName . '.pub';
    }
}
