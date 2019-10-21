<?php
declare(strict_types=1);

namespace RZ\Crypto\Encoder;

use ParagonIE\Halite\Symmetric\Crypto as Symmetric;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

class SymmetricUniqueKeyEncoder implements UniqueKeyEncoderInterface
{
    /** @var EncryptionKey */
    private $key;

    /**
     * UniqueKeyEncoder constructor.
     *
     * @param EncryptionKey $key
     */
    public function __construct(EncryptionKey $key)
    {
        $this->key = $key;
    }

    /**
     * @param HiddenString $toEncode
     *
     * @return string
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function encode(HiddenString $toEncode): string
    {
        return Symmetric::encrypt($toEncode, $this->key);
    }

    /**
     * @param string $encoded
     *
     * @return HiddenString
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidSignature
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function decode(string $encoded): HiddenString
    {
        return Symmetric::decrypt($encoded, $this->key);
    }

    /**
     * @param EncryptionKey $key
     *
     * @return SymmetricUniqueKeyEncoder
     */
    public function setKey(EncryptionKey $key): SymmetricUniqueKeyEncoder
    {
        $this->key = $key;

        return $this;
    }
}
