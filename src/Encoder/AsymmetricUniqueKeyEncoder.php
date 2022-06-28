<?php

declare(strict_types=1);

namespace RZ\Crypto\Encoder;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Asymmetric\EncryptionPublicKey;
use ParagonIE\Halite\Asymmetric\EncryptionSecretKey;
use ParagonIE\Halite\Asymmetric\Crypto as Asymmetric;
use ParagonIE\HiddenString\HiddenString;

class AsymmetricUniqueKeyEncoder implements UniqueKeyEncoderInterface
{
    /** @var EncryptionPublicKey|null */
    private $publicKey;
    /** @var EncryptionSecretKey|null */
    private $privateKey;

    /**
     * AsymmetricUniqueKeyEncoder constructor.
     *
     * @param EncryptionPublicKey|null $publicKey
     * @param EncryptionSecretKey|null $privateKey
     */
    public function __construct(?EncryptionPublicKey $publicKey, ?EncryptionSecretKey $privateKey = null)
    {
        $this->publicKey = $publicKey;
        $this->privateKey = $privateKey;
    }

    /**
     * @param HiddenString $toEncode
     *
     * @return string
     * @throws CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function encode(HiddenString $toEncode): string
    {
        if (null === $this->publicKey) {
            throw new CannotPerformOperation('Cannot encode with NULL public key.');
        }
        return Asymmetric::seal($toEncode, $this->publicKey);
    }

    /**
     * @param string $encoded
     *
     * @return HiddenString
     * @throws CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function decode(string $encoded): HiddenString
    {
        if (null === $this->privateKey) {
            throw new CannotPerformOperation('Cannot decode with NULL private key.');
        }
        return Asymmetric::unseal($encoded, $this->privateKey);
    }

    /**
     * @return EncryptionPublicKey|null
     */
    public function getPublicKey(): ?EncryptionPublicKey
    {
        return $this->publicKey;
    }

    /**
     * @param EncryptionPublicKey $publicKey
     *
     * @return AsymmetricUniqueKeyEncoder
     */
    public function setPublicKey(EncryptionPublicKey $publicKey): AsymmetricUniqueKeyEncoder
    {
        $this->publicKey = $publicKey;

        return $this;
    }

    /**
     * @return EncryptionSecretKey|null
     */
    public function getPrivateKey(): ?EncryptionSecretKey
    {
        return $this->privateKey;
    }

    /**
     * @param EncryptionSecretKey $privateKey
     *
     * @return AsymmetricUniqueKeyEncoder
     */
    public function setPrivateKey(EncryptionSecretKey $privateKey): AsymmetricUniqueKeyEncoder
    {
        $this->privateKey = $privateKey;

        return $this;
    }
}
