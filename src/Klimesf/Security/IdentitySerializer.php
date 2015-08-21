<?php


namespace Klimesf\Security;
use Nette\Security\IIdentity;

/**
 * @package   Klimesf\Security
 * @author    Filip Klimes <filipklimes@startupjobs.cz>
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



}