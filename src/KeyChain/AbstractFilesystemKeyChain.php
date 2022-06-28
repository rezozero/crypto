<?php

declare(strict_types=1);

namespace RZ\Crypto\KeyChain;

use Assert\Assert;

abstract class AbstractFilesystemKeyChain implements KeyChainInterface
{
    /** @var string */
    protected $folder;

    /**
     * FileKeyChain constructor.
     *
     * @param string $folder
     * @param bool   $checkPath
     */
    public function __construct(string $folder, bool $checkPath = true)
    {
        if ($checkPath === true) {
            Assert::that($folder)
                ->notBlank()
                ->directory()
                ->writeable()
                ->readable()
                ->notEq(sys_get_temp_dir(), 'Key cannot be stored in system temporary folder.');
        }
        $this->folder = $folder;
    }

    /**
     * @param string $keyName
     *
     * @return string
     */
    protected function getKeyPath(string $keyName): string
    {
        return $this->folder . DIRECTORY_SEPARATOR . $keyName . '.key';
    }
}
