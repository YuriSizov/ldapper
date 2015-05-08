<?php
/**
 * Ldapper PHP library
 *
 * @author  Yuri Sizov <yuris@humnom.net>
 * @license http://opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @version 1.2
 */
namespace Ldapper;

/**
 * Object representation of AD group
 *
 * @package Ldapper
 */
class DirectoryGroup extends DirectoryObject {
  /**
   * @var array Set of group users by their distinguishedName property
   */
  public $users = array();

  /**
   * @param array            $groupData Group data
   * @param DirectoryManager $manager   Directory manager reference
   */
  public function __construct($groupData, $manager) {
    parent::__construct($groupData, $manager);

    if (isset($this->data['member'])) {
      foreach ($this->data['member'] as $memberDN) {
        $memberCN = DirectoryManager::convertOutputEncoding(str_replace('CN=', '', substr($memberDN, 0, strpos($memberDN, ','))));
        $this->users[$memberCN] = $memberDN;
      }
    }
  }

  /**
   * Add user to this group
   *
   * @param string $userDN User's unique name, distinguishedName property
   * @return bool Operation success status
   */
  public function addUser($userDN) {
    if ($userDN) {
      $this->changes['member'] = $userDN;
      return $this->manager->modGroup($this, DirectoryManager::LDAP_OPER_ADD);
    }
    return false;
  }

  /**
   * Remove user from this group
   *
   * @param string $userDN User's unique name, distinguishedName property
   * @return bool Operation success status
   */
  public function removeUser($userDN) {
    if ($userDN) {
      $this->changes['member'] = $userDN;
      return $this->manager->modGroup($this, DirectoryManager::LDAP_OPER_REMOVE);
    }
    return false;
  }
}