<?php


namespace Klimesf\Security;

use Nette\Security\Identity;
use Nette\Security\IIdentity;

/**
 * @package   Klimesf\Security
 * @author    Filip Klimes <filip@filipklimes.cz>
 * @copyright 2015, Startupedia s.r.o.
 */
class IdentitySerializer implements IIdentitySerializer
{

	/**
	 * Serializes the IIdentity into an array, which will then be stored in
	 * the JWT access token.
	 * @param IIdentity $identity
	 * @return array
	 */
	public function serialize(IIdentity $identity)
	{
		$jwtData['uid'] = $identity->getId();
		$jwtData['roles'] = $identity->getRoles();
		return $jwtData;
	}


	/**
	 * Deserializes the identity data from an array contained in the JWT and
	 * loads into into IIdentity.
	 * @param array $jwtData
	 * @return IIdentity
	 */
	public function deserialize($jwtData)
	{
		return array_key_exists('uid', $jwtData) && array_key_exists('roles', $jwtData)
			? new Identity($jwtData['uid'], $jwtData['roles'])
			: null;
	}
}
