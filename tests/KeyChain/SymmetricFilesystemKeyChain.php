<?php
declare(strict_types=1);

namespace RZ\Crypto\KeyChain\tests\units;

use atoum;

class SymmetricFilesystemKeyChain extends atoum
{
    public function testGenerate()
    {
        $testStoragePath = dirname(__DIR__) . '/storage';
        if (file_exists($testStoragePath . '/SymmetricFilesystemKeyChain.key')) {
            unlink($testStoragePath . '/SymmetricFilesystemKeyChain.key');
        }
        $this
            // création d'une nouvelle instance de la classe à tester
            ->given($keyChain = $this->newTestedInstance($testStoragePath))
            ->then
            ->object($keyChain->generate('SymmetricFilesystemKeyChain'))
        ;
    }

    public function testGet()
    {
        $testStoragePath = dirname(__DIR__) . '/storage';
        $keyChain = $this->newTestedInstance($testStoragePath);
        $this
            ->given($key = $keyChain->generate('SymmetricFilesystemKeyChain'))
            ->then
            ->object($keyChain->get('SymmetricFilesystemKeyChain'))
                ->isEqualTo($key)
        ;
    }
}
