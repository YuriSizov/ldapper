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
require_once "ldapper.user.php";   // AD user representation
require_once "ldapper.group.php";  // AD group representation
require_once "ldapper.helper.php"; // Additional functions
require_once "ldapper.uac.php";    // UAC settings

/**
 * Active directory connection manager for LDAP protocol
 *
 * @package Ldapper
 * @property-read string $lastError Most recent error message
 */
class DirectoryManager {
  /**
   * @var int Action will add supplied data to existing
   */
  const LDAP_OPER_ADD = 1;
  /**
   * @var int Action will replace existing data with supplied
   */
  const LDAP_OPER_MOD = 0;
  /**
   * @var int Action will remove supplied data from existing
   */
  const LDAP_OPER_REMOVE = -1;

  /**
   * @var resource LDAP connection link
   */
  private $link;
  /**
   * @var bool Connection status
   */
  private $connectionOn = false;
  /**
   * @var string Most recent error message
   */
  private $lastError = "";

  /**
   * @var array LDAP connection data, resource host and port
   */
  private $server = array ( 'host' => '', 'port' => '' );
  /**
   * @var string Base path inside AD as Distinguished Name
   */
  private $baseDN;
  /**
   * @var string Base path inside AD as Principal Name
   */
  private $principal;

  /**
   * @var string Path inside AD to a node with groups relative to base path
   */
  private $groupPath;
  /**
   * @var string Current path inside AD relative to base path
   */
  private $currentPath;

  /**
   * @var string Name of a property used as a username (login)
   */
  private $loginProperty;

  /**
   * @var int Maximum number of fetched results
   */
  private $sizeLimit = 1000;

  /**
   * @var array AD group collection
   */
  private $groups = array();
  /**
   * @var array AD user collection
   */
  private $users = array();

  /**
   * @var string Encoding of incoming data
   */
  public static $inputEncoding = "UTF-8";
  /**
   * @var string Encoding of outgoing data
   */
  public static $outputEncoding = "UTF-8";
  /**
   * @var string Inner encoding; always UTF-8
   */
  private static $innerEncoding = "UTF-8";

  /**
   * Convert incoming string to inner encoding
   *
   * @param string $string Incoming string
   * @see $inputEncoding, $innerEncoding
   * @return string Converted string
   */
  public static function convertInputEncoding($string) {
    if (is_string($string)) {
      return iconv(self::$inputEncoding, self::$innerEncoding, $string);
    }
    return $string;
  }

  /**
   * Convert outgoing string to proper encoding
   *
   * @param string $string Outgoing string
   * @see $outputEncoding, $innerEncoding
   * @return string Converted string
   */
  public static function convertOutputEncoding($string) {
    if (is_string($string)) {
      return iconv(self::$innerEncoding, self::$outputEncoding, $string);
    }
    return $string;
  }

  /**
   * @param array|string $server      Connection data as an array with host and port defined, or as a string qualified for parse_url()
   * @param string       $baseDN      Base path inside AD as Distinguished Name
   * @param string       $groupPath   Path inside AD to a node with groups relative to base path
   * @param string       $defaultPath Default path inside AD relative to base path
   *
   * @throws \InvalidArgumentException If connection data, group path or default path are invalid
   * @throws \Exception If connection cannot be established
   */
  public function __construct($server, $baseDN, $groupPath, $defaultPath) {
    $server_arr = array( 'host' => '', 'port' => '' );
    if (is_array($server) && isset($server['host'])) {
      $server_arr['host'] = $server['host'];
      $server_arr['port'] = isset($server['port']) ? $server['port'] : '389';
    }
    else if (is_string($server) && ($url = parse_url($server))) {
      $server_arr['host'] = (isset($url['scheme']) ? $url['scheme'] : 'ldap') . '://' . $url['host'];
      $server_arr['port'] = isset($url['port']) ? $url['port'] : '389';
    }
    else {
      $this->lastError = "[LDAP-CORE] Bad argument: " . var_export($server, true) . ".";
      throw new \InvalidArgumentException($this->lastError);
    }

    $this->server = $server_arr;
    $this->link = ldap_connect($server_arr['host'], $server_arr['port']);
    $this->connectionOn = ((bool) $this->link) && ldap_bind($this->link);
    if (!$this->connectionOn) {
      $this->lastError = "[LDAP-CORE] Couldn't connect to the directory at " . ($server_arr['host'] . ":" . $server_arr['port']) . ".";
      throw new \Exception($this->lastError);
    }

    $this->baseDN = $baseDN;
    $this->principal = '@' . str_replace('DC=', '', str_replace(',DC=', '.', $this->baseDN));
    if (!$this->setGroupPath($groupPath)) {
      $this->lastError = "[LDAP-CORE] Bad argument: " . var_export($groupPath, true) . ".";
      throw new \InvalidArgumentException($this->lastError);
    }
    if (!$this->setPath($defaultPath)) {
      $this->lastError = "[LDAP-CORE] Bad argument: " . var_export($defaultPath, true) . ".";
      throw new \InvalidArgumentException($this->lastError);
    }
  }

  public function __get($property) {
    if (property_exists($this, $property) && in_array($property, array('lastError'))) {
      return $this->$property;
    }
    return null;
  }

  /**
   * Set most recent Ldapper error as most recent LDAP extension error
   */
  private function fetchLDAPError() {
    $errno = ldap_errno($this->link);
    $this->lastError = "[LDAP] " . $errno . ": " . ldap_err2str($errno) . "";
  }
  /**
   * Set most recent Ldapper error as provided
   *
   * @param string $text Error message
   */
  private function setError($text) {
    $this->lastError = "" . $text . "";
  }

  /**
   * Return connection status
   *
   * @return bool Connection status
   */
  public function hasConnection() {
    return $this->connectionOn;
  }

  /**
   * Authorize (or bind) user to AD using supplied credentials
   * This user will be used for every operation, so it must have proper security access
   *
   * @param string $userRDN User relative distinguished name (login)
   * @param string $userPwd User password
   * @return bool Operation success status
   */
  public function open($userRDN, $userPwd) {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if (!(
        ldap_set_option($this->link, LDAP_OPT_PROTOCOL_VERSION, 3)
     && ldap_set_option($this->link, LDAP_OPT_REFERRALS, 0)
     && ldap_set_option($this->link, LDAP_OPT_SIZELIMIT, $this->sizeLimit)
    )) {
      $this->fetchLDAPError();
      return false;
    }

    if (!ldap_bind($this->link, self::convertInputEncoding($userRDN), self::convertInputEncoding($userPwd))) {
      $this->fetchLDAPError();
      return false;
    }

    return true;
  }

  /**
   * Unbind any user connected and end session
   *
   * @return bool Operation success status
   */
  public function close() {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if (!ldap_unbind($this->link)) {
      $this->fetchLDAPError();
      return false;
    }

    return true;
  }

  /**
   * Check if path can be set (e.g. it is valid and exists)
   *
   * @param string $path Path string, relative to base path (e.g. OU=ssl, CN=Users)
   * @return bool Check success status
   */
  public function checkPath($path) {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if ($path == '') {
      $this->setError("[LDAP] Cannot use empty path.");
      return false;
    }

    $resultsLink = ldap_list($this->link, $this->baseDN, '(&(distinguishedname='.($path . ',' . $this->baseDN).'))', array());
    if (!$resultsLink) {
      $this->fetchLDAPError();
      return false;
    }

    if (ldap_count_entries($this->link, $resultsLink) <= 0) {
      $this->setError("[LDAP] Provided path does not exist.");
      return false;
    }
    return true;
  }

  /**
   * Set current path inside AD
   *
   * @param string $path Path string, relative to base path (e.g. OU=ssl, CN=Users)
   * @return bool Operation success status
   */
  public function setPath($path) {
    if ($this->checkPath($path)) {
      $this->currentPath = $path;
      return true;
    }
    return false;
  }

  /**
   * Set path inside AD to a node with groups
   *
   * @param string $path Path string, relative to base path (e.g. OU=ssl, CN=Users)
   * @return bool Operation success status
   */
  public function setGroupPath($path) {
    if ($this->checkPath($path)) {
      $this->groupPath = $path;
      return true;
    }
    return false;
  }

  /**
   * Set the name of property used as a username (login)
   * Note: this does not affect authorization/binding!
   *
   * @param string $name Property name
   * @return bool Operation success status
   */
  public function setLoginProperty($name) {
    if ($name == '') {
      $this->setError('[LDAP] Cannot use empty property name');
      return false;
    }

    $this->loginProperty = $name;
    return true;
  }

  /**
   * Find users matching specified filters and search path (defaults to current path)
   * It can either return a set of usernames (fast and ready for further processing),
   * or a set of object representations (requires more memory)
   * It can as well fetch a set of attributes: the more, the slower it will perform
   *
   * @param array  $filters        A set of filters, each an array itself (key, value[, method]); by default method is 'equals'
   * @param string $searchPath     Search path inside AD (changes current path)
   * @param bool   $deep           If true, DirectoryUser objects will be returned
   * @param array  $deepAttributes If $deep is true, this set will represent attributes to be fetched with DirectoryUser object; '*' (all) is default
   * @return array|bool An array of usernames, or DirectoryUser objects, or FALSE
   */
  public function findUsers($filters, $searchPath = '', $deep = false, $deepAttributes = array('*')) {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if ($searchPath != '' && !$this->setPath($searchPath)) {
      return false;
    }

    if (!is_array($filters) || count($filters) <= 0) {
      $this->setError("[LDAP] Invalid or empty array.");
      return false;
    }

    $filter_str = '';
    foreach ($filters as $filter) {
      if (!isset($filter[2])) $filter[2] = 'equal';
      switch ($filter[2]) {
        case 'equal':
        case '=':
        default:
          $filter_str .= '(' . $filter[0] . '=' . self::convertInputEncoding($filter[1]) . ')';
          break;

        case 'not':
        case '!=':
        case '<>':
          $filter_str .= '(!(' . $filter[0] . '=' . self::convertInputEncoding($filter[1]) . '))';
          break;

        case 'like':
        case '~=':
          $filter_str .= '(' . $filter[0] . '=*' . self::convertInputEncoding($filter[1]) . '*)';
          break;

        case 'gt':
        case '>':
          $filter_str .= '(' . $filter[0] . '>=' . self::convertInputEncoding($filter[1]) . ')(!(' . $filter[0] . '=' . self::convertInputEncoding($filter[1]) . '))';
          break;

        case 'gte':
        case '>=':
          $filter_str .= '(' . $filter[0] . '>=' . self::convertInputEncoding($filter[1]) . ')';
          break;

        case 'lt':
        case '<':
          $filter_str .= '(' . $filter[0] . '<=' . self::convertInputEncoding($filter[1]) . ')(!(' . $filter[0] . '=' . self::convertInputEncoding($filter[1]) . '))';
          break;

        case 'lte':
        case '<=':
          $filter_str .= '(' . $filter[0] . '<=' . self::convertInputEncoding($filter[1]) . ')';
          break;
      }
    }

    if ($deep) {
      if (!$deepAttributes) {
        $deepAttributes = array('*');
      }
    } else {
      $deepAttributes = array('dn');
    }
    $resultsLink = @ldap_search($this->link, $this->currentPath . ',' . $this->baseDN, '(&' . $filter_str . '(objectclass=user))', $deepAttributes);
    if (!$resultsLink) {
      $this->fetchLDAPError();
      return false;
    }

    $results = ldap_get_entries($this->link, $resultsLink);
    if ($results['count'] <= 0) {
      $this->setError("[LDAP] No user found for '" . self::convertOutputEncoding($filter_str) . "'.");
      return false;
    }

    $users = array();
    if (!$deep) {
      for ($i = 0; $i < $results['count']; $i++) {
        $users[] = $results[$i]['dn'];
      }
    }
    else {
      for ($i = 0; $i < $results['count']; $i++) {
        $user = new DirectoryUser($results[$i], $this);
        $this->users[$user->dn] = $user;
        $users[] = $user;
      }
    }
    ldap_free_result($resultsLink);
    return $users;
  }

  /**
   * Get an object representation of a user
   * Error is generated, if more than one user matches supplied data
   *
   * @param string $search     Search data, either commonName or distinguishedName
   * @param string $userPath   Search path inside AD (changes current path)
   * @param array  $attributes Set of attributes to be fetched with DirectoryUser object; '*' (all) is default
   * @return DirectoryUser|bool User object, or FALSE
   */
  public function getUser($search, $userPath = '', $attributes = array('*')) {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }
    $search = self::convertInputEncoding($search);
    if ($userPath != '' && !$this->setPath($userPath)) {
      return false;
    }

    if (!$this->currentPath) {
      $this->setError("[LDAP] No organizational unit is set.");
      return false;
    }

    if (!empty($this->loginProperty)) {
      $filters = '(&(' . $this->loginProperty . '=' . $search . ')(objectclass=user))';
    }
    else if (strpos($search, 'CN=') === 0) {
      $filters = '(&(distinguishedname=' . $search . ')(objectclass=user))';
    }
    else {
      $filters = '(&(cn=' . $search . ')(objectclass=user))';
    }
    if (!$attributes) {
      $attributes = array('*');
    }

    $resultsLink = ldap_search($this->link, $this->currentPath . ',' . $this->baseDN, $filters, $attributes);
    if (!$resultsLink) {
      $this->fetchLDAPError();
      return false;
    }
    $results = ldap_get_entries($this->link, $resultsLink);
    if ($results['count'] <= 0) {
      $this->setError("[LDAP] User '" . self::convertOutputEncoding($search) . "' is not found.");
      return false;
    }

    if ($results['count'] != 1 ) {
      $this->setError("[LDAP] Too many results for '" . self::convertOutputEncoding($search) . "' (" . $results['count'] . " total).");
      ldap_free_result($resultsLink);
      return false;
    }

    try {
      $user = new DirectoryUser($results[0], $this);
    }
    catch (\Exception $e) {
      $this->setError($e->getMessage());
      return false;
    }

    $this->users[$user->dn] = $user;
    ldap_free_result($resultsLink);
    return $user;
  }

  /**
   * Create new user in AD and return it's object representation
   * User is created with password never expires option
   *
   * @param string $userRDN Username (login)
   * @param string $userPwd User password
   * @param string $userPath User path inside AD (changes current path)
   * @return DirectoryUser|bool User object, or FALSE
   */
  public function addUser($userRDN, $userPwd, $userPath = '') {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if ($userPath != '' && !$this->setPath($userPath)) {
      return false;
    }

    if ($this->getUser($userRDN)) {
      $this->setError("[LDAP] This username is already taken.");
      return false;
    }
    $userRDN = self::convertInputEncoding($userRDN);
    $userPwd = self::convertInputEncoding($userPwd);

    $ldaprecord = array();
    $ldaprecord['cn'] = $userRDN;
    $ldaprecord['givenName'] = $userRDN;
    $ldaprecord['displayName'] = $userRDN;
    $ldaprecord['sn'] = $userRDN;
    $ldaprecord['objectclass'][0] = 'top';
    $ldaprecord['objectclass'][1] = 'person';
    $ldaprecord['objectclass'][2] = 'organizationalPerson';
    $ldaprecord['objectclass'][3] = 'user';
    $ldaprecord['sAMAccountName'] = substr($userRDN, 0, 20);
    $ldaprecord['userPrincipalName'] = $userRDN.$this->principal;
    $ldaprecord['unicodePwd'] = DirectoryHelper::convertPassword($userPwd);
    $ldaprecord['userAccountControl'] = DirectoryUAC::ADS_UF_DONT_EXPIRE_PASSWD | DirectoryUAC::ADS_UF_NORMAL_ACCOUNT;

    if (!ldap_add($this->link, 'CN=' . $userRDN . ',' . $this->currentPath . ',' . $this->baseDN, $ldaprecord)) {
      $this->fetchLDAPError();
      return false;
    }

    return $this->getUser($userRDN);
  }

  /**
   * Save changes done to user object to AD
   *
   * @param DirectoryUser $user      User object representation
   * @param int           $operation Kind of operation, defaults to DirectoryManager::LDAP_OPER_MOD
   * @see DirectoryManager::LDAP_OPER_ADD, DirectoryManager::LDAP_OPER_MOD, DirectoryManager::LDAP_OPER_REMOVE
   *
   * @return bool Operation success status
   */
  public function modUser(&$user, $operation = self::LDAP_OPER_MOD) {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if (!($user instanceof DirectoryUser)) {
      $this->setError("[LDAP] Invalid user object.");
      return false;
    }

    $userDN = self::convertOutputEncoding($user->dn);
    if (!$this->getUser($userDN)) {
      return false;
    }
    if (!$this->modObject($user, $operation)) {
      return false;
    }

    $dn = $user->dn;
    $user = $this->getUser($dn);
    return true;
  }

  /**
   * Get an object representation of a group
   * Error is generated, if more than one group matches supplied data
   *
   * @param string $search      Search data, either commonName or distinguishedName
   * @param string $groupPath   Search path inside AD (changes current path)
   * @return DirectoryGroup|bool Group object, or FALSE
   */
  public function getGroup($search, $groupPath = '') {
    if ($this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    $search = self::convertInputEncoding($search);
    if ($groupPath != '' && !$this->setGroupPath($groupPath)) {
      return false;
    }
      
    if (!$this->groupPath) {
      $this->setError("[LDAP] No organizational unit for groups is set.");
      return false;
    }

    if (strpos($search, 'CN=') === 0) {
      $filters = '(&(distinguishedname='.$search.')(objectclass=group))';
    } else {
      $filters = '(&(cn='.$search.')(objectclass=group))';
    }

    $resultsLink = ldap_search($this->link, $this->groupPath . ',' . $this->baseDN, $filters, array('*', 'primarygrouptoken'));
    if (!$resultsLink) {
      $this->fetchLDAPError();
      return false;
    }

    $results = ldap_get_entries($this->link, $resultsLink);
    if ($results['count'] <= 0) {
      $this->setError("[LDAP] Group '" . self::convertOutputEncoding($search) . "' is not found.");
      return false;
    }

    if ($results['count'] != 1) {
      $this->setError("[LDAP] Too many results for '" . self::convertOutputEncoding($search) . "' (" . $results['count'] . " total).");
      ldap_free_result($resultsLink);
      return false;
    }

    $lastSID = '';
    do {
      if ($lastSID != '')
        $resultsPrimaryLink = @ldap_search($this->link, $this->currentPath . ',' . $this->baseDN, '(&(primarygroupid='.$results[0]['primarygrouptoken'][0].')(objectsid>='.$lastSID.')(!(objectsid='.$lastSID.'))(objectclass=user))', array('distinguishedname', 'objectsid'));
      else
        $resultsPrimaryLink = @ldap_search($this->link, $this->currentPath . ',' . $this->baseDN, '(&(primarygroupid='.$results[0]['primarygrouptoken'][0].')(objectclass=user))', array('distinguishedname', 'objectsid'));

      if ($resultsPrimaryLink) {
        $resultsPrimary = ldap_get_entries($this->link, $resultsPrimaryLink);
        $lastCount = $resultsPrimary['count'];

        if (!isset($results[0]['member'])) {
          $results[0]['member'] = array( 'count' => 0 );
          $results[0][] = 'member';
          $results[0]['count'] += 1;
        }

        $results[0]['member']['count'] += $resultsPrimary['count'];
        for ($i = 0; $i < $resultsPrimary['count']; $i++) {
          $results[0]['member'][] = $resultsPrimary[$i]['dn'];
          $lastSID = preg_replace('/../', '\\\\$0', bin2hex($resultsPrimary[$i]['objectsid'][0]));
        }
        ldap_free_result($resultsPrimaryLink);
      }
      else {
        $lastCount = 0;
      }
    } while ($lastCount > 0 && $resultsPrimaryLink);

    try {
      $group = new DirectoryGroup($results[0], $this);
    }
    catch (\Exception $e) {
      $this->setError($e->getMessage());
      return false;
    }

    $this->groups[$group->dn] = $group;
    ldap_free_result($resultsLink);
    return $group;
  }

  /**
   * Get an object representation of a primary group
   *
   * @param int    $token     Numeric token of a primary group
   * @param string $groupPath Search path (changes current path)
   * @return DirectoryGroup|bool Group object, of FALSE
   */
  public function getPrimaryGroup($token, $groupPath = '') {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if ($groupPath != '' && !$this->setGroupPath($groupPath)) {
      return false;
    }
      
    if (!$this->groupPath) {
      $this->setError("[LDAP] No organizational unit for groups is set.");
      return false;
    }
    $resultsLink = ldap_search($this->link, $this->groupPath . ',' . $this->baseDN, '(&(objectclass=group))', array('*', 'primarygrouptoken'));

    if (!$resultsLink) {
      $this->fetchLDAPError();
      return false;
    }
    $results = ldap_get_entries($this->link, $resultsLink);

    if ($results['count'] <= 0) {
      $this->setError("[LDAP] No group is found at path '" . $this->groupPath . "'.");
      return false;
    }

    for ($i = 0; $i < $results['count']; $i++) {
      $groupRaw = $results[$i];
      if ($groupRaw['primarygrouptoken'][0] == $token) {
        try {
          $group = new DirectoryGroup($groupRaw, $this);
        }
        catch (\Exception $e) {
          $this->setError($e->getMessage());
          return false;
        }

        $this->groups[$group->dn] = $group;
        ldap_free_result($resultsLink);
        return $group;
      }
    }

    $this->setError("[LDAP] No matches found for token '" . $token . "' (" . $results['count'] . " checked).");
    ldap_free_result($resultsLink);
    return false;
  }

  /**
   * Save changes done to group object to AD
   *
   * @param DirectoryGroup $group     Group object representation
   * @param int            $operation Kind of operation, defaults to DirectoryManager::LDAP_OPER_MOD
   * @see DirectoryManager::LDAP_OPER_ADD, DirectoryManager::LDAP_OPER_MOD, DirectoryManager::LDAP_OPER_REMOVE
   *
   * @return bool Operation success status
   */
  public function modGroup(&$group, $operation = self::LDAP_OPER_MOD) {
    if (!$this->link) {
      $this->setError("[LDAP] No active connection.");
      return false;
    }

    if (!($group instanceof DirectoryGroup)) {
      $this->setError("[LDAP] Invalid group object.");
      return false;
    }

    $groupDN = self::convertOutputEncoding($group->dn);
    if (!$this->getGroup($groupDN)) {
      return false;
    }
    if (!$this->modObject($group, $operation)) {
      return false;
    }

    $dn = $group->dn;
    $group = $this->getGroup($dn);
    return true;
  }

  /**
   * Internal routine for directory object modifications
   *
   * @param DirectoryObject $object Object representation of AD object (user, group, etc)
   * @param int $operation Kind of operation, defaults to DirectoryManager::LDAP_OPER_MOD
   * @see DirectoryManager::LDAP_OPER_ADD, DirectoryManager::LDAP_OPER_MOD, DirectoryManager::LDAP_OPER_REMOVE
   *
   * @return bool Operation success status
   */
  private function modObject(&$object, $operation = self::LDAP_OPER_MOD) {
    if ($operation == self::LDAP_OPER_ADD) {
      $result = ldap_mod_add($this->link, $object->dn, $object->changes);
    }
    else if ($operation == self::LDAP_OPER_REMOVE) {
      $result = ldap_mod_del($this->link, $object->dn, $object->changes);
    }
    else if ($operation == self::LDAP_OPER_MOD) {
      $result = ldap_mod_replace($this->link, $object->dn, $object->changes);
    }
    else {
      $this->setError("[LDAP] Unknown operation type.");
      return false;
    }

    if (!$result) {
      $this->fetchLDAPError();
      return false;
    }
    return true;
  }
}