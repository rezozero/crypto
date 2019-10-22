<?php
declare(strict_types=1);

namespace RZ\Crypto\Encoder\tests\units;

use atoum;
use ParagonIE\HiddenString\HiddenString;

class ByPassUniqueKeyEncoder extends atoum
{
    public function testEncode()
    {
        $this
            // création d'une nouvelle instance de la classe à tester
            ->given($encoder = $this->newTestedInstance())
            ->then
            ->string($encoder->encode(new HiddenString('secret')))
                ->isEqualTo('secret')
        ;
    }

    public function testDecode()
    {
        $encoder = $this->newTestedInstance();
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
}
