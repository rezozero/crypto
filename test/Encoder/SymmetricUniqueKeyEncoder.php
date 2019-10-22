<?php
declare(strict_types=1);

namespace RZ\Crypto\Encoder\tests\units;

use atoum;
use ParagonIE\HiddenString\HiddenString;
use RZ\Crypto\KeyChain\SymmetricFilesystemKeyChain;

class SymmetricUniqueKeyEncoder extends atoum
{
    public function testEncode()
    {
        $key = $this->getEncryptionKey();

        $this
            // création d'une nouvelle instance de la classe à tester
            ->given($encoder = $this->newTestedInstance($key))
            ->then
            ->string($encoder->encode(new HiddenString('secret')))
                ->isNotEqualTo('secret')
        ;
    }

    public function testDecode()
    {
        $key = $this->getEncryptionKey();
        $encoder = $this->newTestedInstance($key);
        $encrypted = $encoder->encode(new HiddenString('secret'));

        $this
            ->given($decrypted = $encoder->decode($encrypted))
            ->then
            ->boolean($decrypted->getString() === 'secret')
                ->isTrue()
            ->boolean($decrypted->getString() === '==secret')
                ->isFalse()
        ;
    }

    /**
     * @return \ParagonIE\Halite\Key
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\FileError
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    protected function getEncryptionKey()
    {
        $testStoragePath = dirname(__DIR__) . '/storage';
        $keyChain = new SymmetricFilesystemKeyChain($testStoragePath);
        return $keyChain->generate('SymmetricFilesystemKeyChain');
    }
}
