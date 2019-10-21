<?php
declare(strict_types=1);

namespace RZ\Crypto\Encoder;

use ParagonIE\Halite\Alerts\CannotPerformOperation;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\Symmetric\Crypto as Symmetric;
use ParagonIE\Halite\Symmetric\EncryptionKey;
use ParagonIE\HiddenString\HiddenString;

class SymmetricEncoder implements EncoderInterface
{
    /**
     * @param HiddenString $toEncode
     * @param Key          $key
     *
     * @return string
     * @throws CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function encode(HiddenString $toEncode, Key $key): string
    {
        if (!$key instanceof EncryptionKey) {
            throw new CannotPerformOperation('Key must be an EncryptionKey');
        }
        return Symmetric::encrypt($toEncode, $key);
    }

    /**
     * @param string $encoded
     * @param Key    $key
     *
     * @return HiddenString
     * @throws CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidDigestLength
     * @throws \ParagonIE\Halite\Alerts\InvalidMessage
     * @throws \ParagonIE\Halite\Alerts\InvalidSignature
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function decode(string $encoded, Key $key): HiddenString
    {
        if (!$key instanceof EncryptionKey) {
            throw new CannotPerformOperation('Key must be an EncryptionKey');
        }
        return Symmetric::decrypt($encoded, $key);
    }
}
