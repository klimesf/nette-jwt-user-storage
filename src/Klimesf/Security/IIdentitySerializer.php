<?php


namespace Klimesf\Security;

use Nette\Security\IIdentity;

/**
 * Interface for IIdentity serializer used to serialize your implementation
 * of Nette\Security\IIdentity and store the data in the JWT access token.
 * @package   Klimesf\Security
 * @author    Filip Klimes <filipklimes@startupjobs.cz>
 */
interface IIdentitySerializer
{

	/**
	 * Serializes the IIdentity into an array, which will then be stored in
	 * the JWT access token.
	 * @param IIdentity $identity
	 * @return array
	 */
	public function serialize(IIdentity $identity);

}