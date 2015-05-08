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
 * Object representation of a generic AD object
 *
 * @package Ldapper
 */
class DirectoryObject {
  /**
   * @var DirectoryManager Directory manager reference
   */
  protected $manager;

  /**
   * @var string Object's unique name, distinguishedName property
   */
  public $dn = "";
  /**
   * @var array Fetched object data, attributes (inner encoding)
   */
  public $data = array();
  /**
   * @var array A set of changed data, attributes (inner encoding)
   */
  public $changes = array();


  /**
   * @param array            $objectData Object data
   * @param DirectoryManager $manager    Directory manager reference
   */
  public function __construct($objectData, $manager) {
    if (!is_array($objectData) || empty($objectData) || !($manager instanceof DirectoryManager)) {
      throw new \InvalidArgumentException("[LDAP-OBJECT] Unable to create an object representation, bad arguments");
    }

    $this->manager = $manager;

    for ($i = 0; $i < $objectData['count']; $i++) {
      $k = $objectData[$i];
      if ($objectData[$k]['count'] == 1 && !in_array($k, array('objectclass','memberof','member','altsecurityidentities','msmqdigests','directreports'))) {
        $this->data[$k] = $objectData[$k][0];
      }
      else {
        for ($j = 0; $j < $objectData[$k]['count']; $j++) {
          $this->data[$k][$j] = $objectData[$k][$j];
        }
      }
    }
    $this->dn = $objectData['dn'];
  }

  /**
   * Get data (attribute) value, converted to a proper encoding and pre-processed for better human comprehension
   *
   * @param string $attribute     Attribute name
   * @param bool   $ignoreChanges If true, then changes not yet saved won't be used
   * @return mixed|bool
   */
  public function getData($attribute, $ignoreChanges = false) {
    if ($attribute) {
      $value = false;
      $attribute = strtolower($attribute);
      if (!$ignoreChanges && isset($this->changes[$attribute])) {
        $value = $this->changes[$attribute];
      }
      else if (isset($this->data[$attribute])) {
        $value = $this->data[$attribute];
      }

      if ($value === false)
        return false;

      if (!is_array($value)) {
        switch ($attribute) {
          case 'objectguid':
          case 'objectsid':
          case 'msmqsigncertificates':
            return bin2hex($value);

          case 'lastlogon':
          case 'lastlogontimestamp':
          case 'lastlogoff':
          case 'badpasswordtime':
          case 'pwdlastset':
            return ($value != 0 ? date("d.m.Y H:i:s", $value/10000000-11644473600) : 0);

          case 'accountexpires':
            return ($value != 0 && $value != 9223372036854775807 ? date("d.m.Y H:i:s", $value/10000000-11644473600) : 0);

          case 'whencreated':
          case 'whenchanged':
          return date("d.m.Y H:i:s", strtotime(substr($value,6,2) . '.' . substr($value,4,2) . '.' . substr($value,0,4) . ' ' . substr($value,8,2) . ':' . substr($value,10,2) . ':' . substr($value,12,2)));

          default:
            return DirectoryManager::convertOutputEncoding($value);
        }
      }
      else {
        foreach ($value as $k=>$v) {
          switch ($attribute) {
            case 'msmqdigests':
              $value[$k] = bin2hex($v);
              break;

            case 'dscorepropagationdata':
              $value[$k] = date("d.m.Y H:i:s", strtotime(substr($v,6,2) . '.' . substr($v,4,2) . '.' . substr($v,0,4) . ' ' . substr($v,8,2) . ':' . substr($v,10,2) . ':' . substr($v,12,2)));
              break;

            default:
              $value[$k] = DirectoryManager::convertOutputEncoding($v);
              break;
          }
        }
        return $value;
      }
    }
    return false;
  }

  /**
   * Set data (attribute) value
   * This operation can be performed manually on $changes set, but be mindful of encoding and attribute names
   *
   * @param string             $attribute Attribute name
   * @param string|array|mixed $value     Attribute value
   */
  public function setData($attribute, $value) {
    if ($attribute && $value) {
      $attribute = strtolower($attribute);
      if (!is_array($value)) {
        $value = DirectoryManager::convertInputEncoding($value);

        if ($attribute == 'unicodepwd') {
          $value = DirectoryHelper::convertPassword($value);
        }
      }
      else {
        foreach ($value as $k=>$v) {
          $value[$k] = DirectoryManager::convertInputEncoding($v);
        }
      }
      $this->changes[$attribute] = $value;
    }
  }
}