<?php

declare(strict_types=1);

namespace RZ\Crypto\KeyChain;

use Doctrine\DBAL\Connection;
use ParagonIE\Halite\Alerts\HaliteAlertInterface;
use ParagonIE\Halite\Alerts\InvalidKey;
use ParagonIE\Halite\Key;
use ParagonIE\Halite\KeyFactory;
use RZ\Crypto\Encoder\UniqueKeyEncoderInterface;

/**
 * Encrypted database table for all keys.
 *
 * @package RZ\Crypto\Key
 */
class SymmetricDatabaseKeyChain implements KeyChainInterface
{
    private Connection $connection;
    private string $tableName;
    private string $keyNameColumn;
    private string $keyContentColumn;
    private UniqueKeyEncoderInterface $masterEncoder;

    /**
     * @param Connection                $connection
     * @param UniqueKeyEncoderInterface $masterEncoder
     * @param string                    $tableName
     * @param string                    $keyNameColumn
     * @param string                    $keyContentColumn
     */
    public function __construct(
        Connection $connection,
        UniqueKeyEncoderInterface $masterEncoder,
        string $tableName,
        string $keyNameColumn,
        string $keyContentColumn
    ) {
        $this->connection = $connection;
        $this->tableName = $tableName;
        $this->keyNameColumn = $keyNameColumn;
        $this->keyContentColumn = $keyContentColumn;
        $this->masterEncoder = $masterEncoder;
    }

    /**
     * @param string $keyName
     *
     * @return Key
     * @throws InvalidKey
     * @throws \Doctrine\DBAL\DBALException
     */
    public function get(string $keyName): Key
    {
        $qb = $this->connection->createQueryBuilder();
        $qb->select($this->keyContentColumn)
            ->from($this->tableName)
            ->andWhere($qb->expr()->eq($this->keyNameColumn, ':keyName'))
            ->setMaxResults(1)
            ->setParameter(':keyName', $keyName)
        ;
        $keyContent = $this->connection->executeQuery($qb->getSQL())->fetchOne();
        if (!\is_string($keyContent)) {
            throw new InvalidKey('Key content from database is not valid.');
        }
        return KeyFactory::importEncryptionKey($this->masterEncoder->decode((string) $keyContent));
    }

    /**
     * @param Key    $key
     * @param string $keyName
     *
     * @throws \Doctrine\DBAL\DBALException
     * @throws \ParagonIE\Halite\Alerts\CannotPerformOperation
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function save(Key $key, string $keyName): void
    {
        $this->connection->insert($this->tableName, [
            $this->keyNameColumn => $keyName,
            $this->keyContentColumn => $this->masterEncoder->encode(KeyFactory::export($key))
        ]);
    }

    public function generate(string $keyName): Key
    {
        try {
            $encKey = $this->get($keyName);
        } catch (HaliteAlertInterface $e) {
            $encKey = KeyFactory::generateEncryptionKey();
            $this->save($encKey, $keyName);
        }
        return $encKey;
    }
}
