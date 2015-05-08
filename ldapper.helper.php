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
 * Helper functions that may be useful outside Ldapper
 *
 * @package Ldapper
 */
class DirectoryHelper {
  /**
   * Convert user password to a qualified format
   *
   * @param string $userPwd Password string
   * @return string Qualified password
   */
  public static function convertPassword($userPwd) {
    $userPwdUnicode = '';
    $userPwd = '"' . $userPwd . '"';
    $userPwdLen = strlen($userPwd);

    for ($i = 0; $i < $userPwdLen; $i++) {
      $userPwdUnicode .= "{$userPwd{$i}}\000";
    }

    return $userPwdUnicode;
  }

  /**
   * Create a qualified string for X.509 name mapping
   *
   * @param string $certificate_string Certificate as a string
   * @param bool $b64 If true, then certificate string is treated as Base64 string, DER (binary) otherwise; defaults to an educated guess
   * @return string Qualified mapping string
   */
  public static function createX509MappingString($certificate_string, $b64 = null) {
    if ($b64 === null) {
      $b64 = (strpos($certificate_string, '-----BEGIN CERTIFICATE-----') !== false);
    }
    if ($b64) {
      $parsed_data = openssl_x509_parse($certificate_string);
    } else {
      $parsed_data = openssl_x509_parse("-----BEGIN CERTIFICATE-----\n" . chunk_split(base64_encode($certificate_string), 64, "\n") . "-----END CERTIFICATE-----\n");
    }
    if (!$parsed_data) {
      return "";
    }
    function utf16_routine($utf16_string) {
      $utf16be_chars = array(
        '\x04\x10' => iconv('windows-1251', 'utf-8', 'А'), '\x04\x11' => iconv('windows-1251', 'utf-8', 'Б'), '\x04\x12' => iconv('windows-1251', 'utf-8', 'В'), '\x04\x13' => iconv('windows-1251', 'utf-8', 'Г'), '\x04\x14' => iconv('windows-1251', 'utf-8', 'Д'), '\x04\x15' => iconv('windows-1251', 'utf-8', 'Е'), '\x04\x01' => iconv('windows-1251', 'utf-8', 'Ё'), '\x04\x16' => iconv('windows-1251', 'utf-8', 'Ж'), '\x04\x17' => iconv('windows-1251', 'utf-8', 'З'), '\x04\x18' => iconv('windows-1251', 'utf-8', 'И'), '\x04\x19' => iconv('windows-1251', 'utf-8', 'Й'), '\x04\x1A' => iconv('windows-1251', 'utf-8', 'К'), '\x04\x1B' => iconv('windows-1251', 'utf-8', 'Л'), '\x04\x1C' => iconv('windows-1251', 'utf-8', 'М'), '\x04\x1D' => iconv('windows-1251', 'utf-8', 'Н'), '\x04\x1E' => iconv('windows-1251', 'utf-8', 'О'), '\x04\x1F' => iconv('windows-1251', 'utf-8', 'П'), '\x04 ' => iconv('windows-1251', 'utf-8', 'Р'), '\x04!' => iconv('windows-1251', 'utf-8', 'С'), '\x04"' => iconv('windows-1251', 'utf-8', 'Т'), '\x04#' => iconv('windows-1251', 'utf-8', 'У'), '\x04$' => iconv('windows-1251', 'utf-8', 'Ф'), '\x04%' => iconv('windows-1251', 'utf-8', 'Х'), '\x04&' => iconv('windows-1251', 'utf-8', 'Ц'), '\x04\'' => iconv('windows-1251', 'utf-8', 'Ч'), '\x04(' => iconv('windows-1251', 'utf-8', 'Ш'), '\x04)' => iconv('windows-1251', 'utf-8', 'Щ'), '\x04*' => iconv('windows-1251', 'utf-8', 'Ъ'), '\x04+' => iconv('windows-1251', 'utf-8', 'Ы'), '\x04,' => iconv('windows-1251', 'utf-8', 'Ь'), '\x04-' => iconv('windows-1251', 'utf-8', 'Э'), '\x04.' => iconv('windows-1251', 'utf-8', 'Ю'), '\x04/' => iconv('windows-1251', 'utf-8', 'Я'),
        '\x040' => iconv('windows-1251', 'utf-8', 'а'), '\x041' => iconv('windows-1251', 'utf-8', 'б'), '\x042' => iconv('windows-1251', 'utf-8', 'в'), '\x043' => iconv('windows-1251', 'utf-8', 'г'), '\x044' => iconv('windows-1251', 'utf-8', 'д'), '\x045' => iconv('windows-1251', 'utf-8', 'е'), '\x04Q' => iconv('windows-1251', 'utf-8', 'ё'), '\x046' => iconv('windows-1251', 'utf-8', 'ж'), '\x047' => iconv('windows-1251', 'utf-8', 'з'), '\x048' => iconv('windows-1251', 'utf-8', 'и'), '\x049' => iconv('windows-1251', 'utf-8', 'й'), '\x04:' => iconv('windows-1251', 'utf-8', 'к'), '\x04;' => iconv('windows-1251', 'utf-8', 'л'), '\x04<' => iconv('windows-1251', 'utf-8', 'м'), '\x04=' => iconv('windows-1251', 'utf-8', 'н'), '\x04>' => iconv('windows-1251', 'utf-8', 'о'), '\x04?' => iconv('windows-1251', 'utf-8', 'п'), '\x04@' => iconv('windows-1251', 'utf-8', 'р'), '\x04A' => iconv('windows-1251', 'utf-8', 'с'), '\x04B' => iconv('windows-1251', 'utf-8', 'т'), '\x04C' => iconv('windows-1251', 'utf-8', 'у'), '\x04D' => iconv('windows-1251', 'utf-8', 'ф'), '\x04E' => iconv('windows-1251', 'utf-8', 'х'), '\x04F' => iconv('windows-1251', 'utf-8', 'ц'), '\x04G' => iconv('windows-1251', 'utf-8', 'ч'), '\x04H' => iconv('windows-1251', 'utf-8', 'ш'), '\x04I' => iconv('windows-1251', 'utf-8', 'щ'), '\x04J' => iconv('windows-1251', 'utf-8', 'ъ'), '\x04K' => iconv('windows-1251', 'utf-8', 'ы'), '\x04L' => iconv('windows-1251', 'utf-8', 'ь'), '\x04M' => iconv('windows-1251', 'utf-8', 'э'), '\x04N' => iconv('windows-1251', 'utf-8', 'ю'), '\x04O' => iconv('windows-1251', 'utf-8', 'я'),
        '\x00.' => '.', '\x00,' => ',', '\x00:' => ':', '\x00;' => ';', '\x00 ' => ' ', '\x00\'' => '\'', '\x00"' => '"', '\x00-' => '-', '\x00+' => '+', '\x00=' => '=', '\x00(' => '(', '\x00)' => ')', '\x00<' => '<', '\x00>' => '>', '\x00{' => '{', '\x00}' => '}', '\x00[' => '[', '\x00]' => ']', '\x00|' => '|', '\x00!' => '!', '\x00?' => '?', '\x00@' => '@', '\x00#' => '#', '\x00$' => '$', '\x00%' => '%', '\x00^' => '^', '\x00&' => '&', '\x00*' => '*',
        '!\x16' => iconv('windows-1251', 'utf-8', '№'), '\x00\xAB' => iconv('windows-1251', 'utf-8', '«'), '\x00\xBB' => iconv('windows-1251', 'utf-8', '»'),
        '\x001' => '1', '\x002' => '2', '\x003' => '3', '\x004' => '4', '\x005' => '5', '\x006' => '6', '\x007' => '7', '\x008' => '8', '\x009' => '9', '\x000' => '0', '\x00`' => '`',
        '\x00A' => 'A', '\x00B' => 'B', '\x00C' => 'C', '\x00D' => 'D', '\x00E' => 'E', '\x00F' => 'F', '\x00G' => 'G', '\x00H' => 'H', '\x00I' => 'I', '\x00J' => 'J', '\x00K' => 'K', '\x00L' => 'L', '\x00M' => 'M', '\x00N' => 'N', '\x00O' => 'O', '\x00P' => 'P', '\x00Q' => 'Q', '\x00R' => 'R', '\x00S' => 'S', '\x00T' => 'T', '\x00U' => 'U', '\x00V' => 'V', '\x00W' => 'W', '\x00X' => 'X', '\x00Y' => 'Y', '\x00Z' => 'Z',
        '\x00a' => 'a', '\x00b' => 'b', '\x00c' => 'c', '\x00d' => 'd', '\x00e' => 'e', '\x00f' => 'f', '\x00g' => 'g', '\x00h' => 'h', '\x00i' => 'i', '\x00j' => 'j', '\x00k' => 'k', '\x00l' => 'l', '\x00m' => 'm', '\x00n' => 'n', '\x00o' => 'o', '\x00p' => 'p', '\x00q' => 'q', '\x00r' => 'r', '\x00s' => 's', '\x00t' => 't', '\x00u' => 'u', '\x00v' => 'v', '\x00w' => 'w', '\x00x' => 'x', '\x00y' => 'y', '\x00z' => 'z',
        '\x00/' => '/', '\x00\\' => '\\',
      );
      $utf16_string = str_replace(array_keys($utf16be_chars), array_values($utf16be_chars), $utf16_string);

      $output = array();
      $vm = array();
      $vr = array();
      preg_match_all('/\\\x[0-9A-F]{2}/i', $utf16_string, $vm);
      foreach ($vm[0] as $vk => $vv) {
        $vr[$vk] = chr(hexdec(substr($vv, 2, 2)));
      }
      $utf16_string = str_replace($vm[0], $vr, $utf16_string);

      $subject = explode('/', $utf16_string);
      $subjectc = count($subject);
      $last_output = null;
      for ($i = 1; $i < $subjectc; $i++) {
        $subject_part = $subject[$i];
        $subject_exp = explode('=', $subject_part, 2);
        if (!isset($subject_exp[1])) {
          $last_output .= '/' . $subject_part;
          continue;
        }
        if (empty($subject_exp[1]) && isset($subject[$i+1]) && $subject[$i+1] == '') {
          $subject_exp[1] = '/';
          $i++;
        }
        list($k, $v) = $subject_exp;
        if (preg_match('/^[0-9](\.[0-9]+)+$/', $k) === 1) {
          $k = 'OID.' . $k;
        }
        $output[$k] = $v;
        $last_output = &$output[$k];
      }
      return $output;
    }
    $parsed_data['subject'] = utf16_routine($parsed_data['name']);

    $issuer = '';
    if (isset($parsed_data['extensions']['authorityKeyIdentifier'])) {
      $issuer_ext = explode(chr(10), $parsed_data['extensions']['authorityKeyIdentifier']);
      foreach ($issuer_ext as $ext) {
        if (strpos($ext, 'DirName:') === 0) {
          $issuer = substr($ext, 8);
          break;
        }
      }
    }
    $parsed_data['issuer'] = array_merge(utf16_routine($issuer), $parsed_data['issuer']);

    function replacement_routine($arr) {
      $codesReplacement = array( 'initials' => 'I', 'title' => 'T', 'emailAddress' => 'E', 'ST' => 'S', 'GN' => 'G', 'postalAddress' => 'OID.2.5.4.16', 'street' => 'STREET', 'pseudonym' => 'OID.2.5.4.65' );
      $output = '';

      foreach($arr as $k=>$v) {
        if (isset($codesReplacement[$k])) $k = $codesReplacement[$k];
        $strpos_quot = strpos($v, '"');
        $strpos_esc = strpbrk($v, ',');
        if (($strpos_quot !== false && $strpos_quot >= 0) || $strpos_esc !== false) {
          $v = '"' . str_replace('"', '""', $v) . '"';
        }
        $output .= $k . '=' . $v . ',';
      }
      $output = substr($output, 0, -1);
      return $output;
    }
    return 'X509:<I>' . replacement_routine($parsed_data['issuer']) . '<S>' . replacement_routine($parsed_data['subject']);
  }
}