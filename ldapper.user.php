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
 * Object representation of AD user
 *
 * @package Ldapper
 */
class DirectoryUser extends DirectoryObject {
  /**
   * @var array Set of user group objects (primary defined separately from others)
   */
  public $groups = array( 'primary' => null );

  /**
   * @param array            $userData User data
   * @param DirectoryManager $manager  Directory manager reference
   */
  public function __construct($userData, $manager) {
    parent::__construct($userData, $manager);

    if (isset($this->data['memberof'])) {
      foreach ($this->data['memberof'] as $groupDN) {
        $groupDN = DirectoryManager::convertOutputEncoding($groupDN);
        $this->groups[] = $this->manager->getGroup($groupDN);
      }
    }

    if (isset($this->data['primarygroupid'])) {
      $this->groups['primary'] = $this->manager->getPrimaryGroup($this->data['primarygroupid']);
    }
  }

  /**
   * Make user account active/enabled
   */
  public function enable() {
    $this->changes['useraccountcontrol'] = $this->getData('useraccountcontrol') | DirectoryUAC::ADS_UF_ACCOUNT_DISABLE;
  }

  /**
   * Make user account inactive/disabled
   */
  public function disable() {
    $this->changes['useraccountcontrol'] = $this->getData('useraccountcontrol') & ~DirectoryUAC::ADS_UF_ACCOUNT_DISABLE;
  }

  /**
   * Get account enabled/disabled state
   *
   * @return bool Account state
   */
  public function isEnabled() {
    return !($this->hasUAC(DirectoryUAC::ADS_UF_ACCOUNT_DISABLE));
  }

  /**
   * Check bit mask to match user's UAC settings
   *
   * @param int $uac_bit Bit mask set as one DirectoryUAC constant or an expression of several; e.g. (DirectoryUAC::ADS_UF_ACCOUNT_DISABLE | DirectoryUAC::ADS_UF_DONT_EXPIRE_PASSWD)
   * @return bool Check success status
   */
  public function hasUAC($uac_bit) {
    return (($this->getData('useraccountcontrol') & $uac_bit) === $uac_bit);
  }

  /**
   * Change user password
   *
   * @param string $password New user password
   */
  public function setPassword($password) {
    if ($password) {
      $password = DirectoryManager::convertInputEncoding($password);
      $password = DirectoryHelper::convertPassword($password);
      $this->changes['unicodepwd'] = $password;
    }
  }

  /**
   * Name map X509 certificate from file
   *
   * @param string $file File path
   * @param bool   $b64  If true, then certificate string is treated as Base64 string, DER (binary) otherwise; defaults to an educated guess
   * @return bool Operation success status
   */
  public function mapX509($file, $b64 = null) {
    if (file_exists($file)) {
      return $this->mapX509String(file_get_contents($file), $b64);
    }
    return false;
  }

  /**
   * Name map X509 certificate from string
   *
   * @param string $certificate_string Certificate string
   * @param bool   $b64                If true, then certificate string is treated as Base64 string, DER (binary) otherwise; defaults to an educated guess
   * @return bool Operation success status
   */
  public function mapX509String($certificate_string, $b64 = null) {
    $certString = DirectoryHelper::createX509MappingString($certificate_string, $b64);
    if ($certString) {
      if (isset($this->changes['altsecurityidentities']) && is_array($this->changes['altsecurityidentities']) && count($this->changes['altsecurityidentities']) > 0) {
        $this->changes['altsecurityidentities'][] = $certString;
      }
      elseif (isset($this->data['altsecurityidentities']) && is_array($this->data['altsecurityidentities']) && count($this->data['altsecurityidentities']) > 0) {
        $this->changes['altsecurityidentities'] = $this->data['altsecurityidentities'];
        $this->changes['altsecurityidentities'][count($this->data['altsecurityidentities'])] = $certString;
      }
      else {
        $this->changes['altsecurityidentities'] = array();
        $this->changes['altsecurityidentities'][0] = $certString;
      }
      return true;
    }
    return false;
  }

  /**
   * Inner routine for X509 name mapping parsing
   * A state machine of sorts
   *
   * @param string $str Part of X509 mapping string
   * @return array Parsed data
   */
  private function parseX509($str) {
    $len = strlen($str);
    $arr = array();
    $buffer = "";
    $state = 0; // 0 - key, 1 - value
    $open_quote = false;

    $key = "";
    $value = "";

    for ($i = 0; $i < $len; $i++) {
      $char = $str[$i];
      if ($state === 0) {
        if ($char == "=") {
          $key = $buffer;
          $buffer = "";
          $state = 1;
        } else {
          $buffer .= $char;
        }
      }
      elseif ($state === 1) {
        if ($char == '"') {
          if ($open_quote) {
            if (isset($str[$i+1]) && $str[$i+1] == '"') {
              $buffer .= $char;
              $i++;
            } else {
              $open_quote = false;
            }
          } else {
            $open_quote = true;
          }
        } else {
          if (!$open_quote && $char == ",") {
            $value = $buffer;
            $buffer = "";
            $state = 0;
            $arr[$key] = $value;
          } else {
            $buffer .= $char;
          }
        }
      }
    }

    if ($buffer != "" && isset($char)) {
      $value = $buffer;
      $arr[$key] = $value;
    }
    return $arr;
  }

  /**
   * Get name mappings (X509 and Kerberos, as well as others unknown)
   *
   * @return array Set of name mappings
   */
  public function getMappings() {
    $mappings = array( 'x509' => array(), 'kerberos' => array(), 'other' => array() );

    if (isset($this->data['altsecurityidentities']) && is_array($this->data['altsecurityidentities'])) {
      foreach ($this->data['altsecurityidentities'] as $identity) {
        $identity = DirectoryManager::convertOutputEncoding($identity);
        $mapping = explode(':', $identity, 2);

        switch($mapping[0]) {
          case 'X509':
            $x509_arr = explode('<S>', str_replace('<I>', '', $mapping[1]));

            $id_issuer = $this->parseX509($x509_arr[0]);
            $id_subject = $this->parseX509($x509_arr[1]);
            $mappings['x509'][] = array( 'issuer' => $id_issuer, 'subject' => $id_subject, 'rawData' => $identity );
            break;

          case 'Kerberos':
            $mappings['kerberos'][] = array( 'rawData' => $identity );
            break;

          default:
            if (count($mapping) == 2) {
              $mappings['other'][] = array( 'type' => $mapping[0], 'rawData' => $identity );
            }
            else {
              $mappings['other'][] = array( 'type' => 'unknown', 'rawData' => $identity );
            }
            break;
        }
      }
    }

    return $mappings;
  }

  /**
   * Add this user to group
   *
   * @param string $groupDN Group's unique name, distinguishedName property
   * @return bool Operation success status
   */
  public function addGroup($groupDN) {
    if ($groupDN) {
      $groupDN = DirectoryManager::convertOutputEncoding($groupDN);
      $group = $this->manager->getGroup($groupDN);

      if ($group) {
        return $group->addUser($this->dn);
      }
      else {
        return false;
      }
    }
    return false;
  }

  /**
   * Remove this user from group
   *
   * @param string $groupDN Group's unique name, distinguishedName property
   * @return bool Operation success status
   */
  public function removeGroup($groupDN) {
    if ($groupDN) {
      $groupDN = DirectoryManager::convertOutputEncoding($groupDN);
      $group = $this->manager->getGroup($groupDN);
      if ($group) {
        return $group->removeUser($this->dn);
      }
      else {
        return false;
      }
    }
    return false;
  }
}