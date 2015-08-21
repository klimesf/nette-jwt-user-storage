<?php


namespace Klimesf\Security\DI;

use Nette\DI\CompilerExtension;

/**
 * Nette DI extension which registers JWTUserStorage.
 * @package   Klimesf\Security\DI
 * @author    Filip Klimes <filip@filipklimes.cz>
 */
class JWTUserStorageExtension extends CompilerExtension
{

	private $defaults = [
		'identitySerializer' => 'Klimesf\Security\IdentitySerializer',
	];

	public function loadConfiguration()
	{
		$builder = $this->getContainerBuilder();
		$config = $this->getConfig($this->defaults);
		if (!array_key_exists('privateKey', $config) || !array_key_exists('algorithm', $config)) {
			throw new \UnexpectedValueException("Please configure the JWTUserStorage extensions using the section " .
				"'{$this->name}:' in your config file.");
		}

		$builder->addDefinition($this->prefix('firebaseJWTWrapper'))
			->setClass('Klimesf\Security\JWT\FirebaseJWTWrapper');

		$builder->addDefinition($this->prefix('jwtUserStorage'))
			->setClass('Klimesf\Security\JWTUserStorage', [$config['privateKey'], $config['algorithm']]);

		$builder->addDefinition($this->prefix('identitySerializer'))
			->setClass($config['identitySerializer']);

		// Disable Nette's default IUserStorage implementation
		$builder->getDefinition('security.userStorage')->setAutowired(false);
	}
}
