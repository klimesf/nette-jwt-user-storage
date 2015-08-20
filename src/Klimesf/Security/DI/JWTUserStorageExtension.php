<?php


namespace Klimesf\Security\DI;

use Nette\DI\CompilerExtension;

/**
 * Nette DI extension which registers JWTUserStorage.
 * @package   Klimesf\Security\DI
 * @author    Filip Klimes <filipklimes@startupjobs.cz>
 */
class JWTUserStorageExtension extends CompilerExtension
{

	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();
		$config = $this->getConfig();
		if (!array_key_exists('privateKey', $config) || !array_key_exists('algorithm', $config)) {
			throw new \UnexpectedValueException("Please configure the JWTUserStorage extensions using the section " .
				"'{$this->name}:' in your config file.");
		}

		$builder->addDefinition($this->prefix('firebaseJWTService'))
			->setClass('Klimesf\Security\JWT\FirebaseJWTService');

		$builder->addDefinition($this->prefix('jwtUserStorage'))
			->setClass('Klimesf\Security\JWTUserStorage', [$config['privateKey'], $config['algorithm']]);
	}
}