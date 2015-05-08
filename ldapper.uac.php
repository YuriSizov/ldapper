<?php
/**
 * Ldapper PHP library
 *
 * @author  Yuri Sizov <yuris@humnom.net>
 * @license http: * @var int opensource.org/licenses/MIT The MIT License (MIT)
 *
 * @version 1.2
 */
namespace Ldapper;

/**
 * Enumeration of user account control (UAC) options
 *
 * @package Ldapper
 */
class DirectoryUAC {
  /**
   * @var int D (ADS_UF_ACCOUNT_DISABLE, 0x00000002): Specifies that the account is not enabled for authentication.
   */
  const ADS_UF_ACCOUNT_DISABLE = 2;
  /**
   * @var int HR (ADS_UF_HOMEDIR_REQUIRED, 0x00000008): Specifies that the homeDirectory attribute is required.
   */
  const ADS_UF_HOMEDIR_REQUIRED = 8;
  /**
   * @var int L (ADS_UF_LOCKOUT, 0x00000010): Specifies that the account is temporarily locked out.
   */
  const ADS_UF_LOCKOUT = 16;
  /**
   * @var int NR (ADS_UF_PASSWD_NOTREQD, 0x00000020): Specifies that the password-length policy, as specified in [MS-SAMR] section 3.1.1.8.1, does not apply to this user.
   */
  const ADS_UF_PASSWD_NOTREQD = 32;
  /**
   * @var int CC (ADS_UF_PASSWD_CANT_CHANGE, 0x00000040): Specifies that the user cannot change his or her password.
   */
  const ADS_UF_PASSWD_CANT_CHANGE = 64;
  /**
   * @var int ET (ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED, 0x00000080): Specifies that the cleartext password is to be persisted.
   */
  const ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED = 128;
  /**
   * @var int N (ADS_UF_NORMAL_ACCOUNT, 0x00000200): Specifies that the account is the default account type that represents a typical user.
   */
  const ADS_UF_NORMAL_ACCOUNT = 512;
  /**
   * @var int ID (ADS_UF_INTERDOMAIN_TRUST_ACCOUNT, 0x00000800): Specifies that the account is for a domain-to-domain trust.
   */
  const ADS_UF_INTERDOMAIN_TRUST_ACCOUNT = 2048;
  /**
   * @var int WT (ADS_UF_WORKSTATION_TRUST_ACCOUNT, 0x00001000): Specifies that the account is a computer account for a computer that is a member of this domain.
   */
  const ADS_UF_WORKSTATION_TRUST_ACCOUNT = 4096;
  /**
   * @var int ST (ADS_UF_SERVER_TRUST_ACCOUNT, 0x00002000): Specifies that the account is a computer account for a DC.
   */
  const ADS_UF_SERVER_TRUST_ACCOUNT = 8192;
  /**
   * @var int DP (ADS_UF_DONT_EXPIRE_PASSWD, 0x00010000): Specifies that the password does not expire for the account.
   */
  const ADS_UF_DONT_EXPIRE_PASSWD = 65536;
  /**
   * @var int 
   */
  const ADS_UF_MNS_LOGON_ACCOUNT = 131072;
  /**
   * @var int SR (ADS_UF_SMARTCARD_REQUIRED, 0x00040000): Specifies that a smart card is required to log in to the account.
   */
  const ADS_UF_SMARTCARD_REQUIRED = 262144;
  /**
   * @var int TD (ADS_UF_TRUSTED_FOR_DELEGATION, 0x00080000): Used by the Kerberos protocol. This bit indicates that the "OK as Delegate" ticket flag, as described in [RFC4120] section 2.8, MUST be set.
   */
  const ADS_UF_TRUSTED_FOR_DELEGATION = 524288;
  /**
   * @var int ND (ADS_UF_NOT_DELEGATED, 0x00100000): Used by the Kerberos protocol. This bit indicates that the ticket-granting tickets (TGTs) of this account and the service tickets obtained by this account are not marked as forwardable or proxiable when the forwardable or proxiable ticket flags are requested. For more information, see [RFC4120].
   */
  const ADS_UF_NOT_DELEGATED = 1048576;
  /**
   * @var int DK (ADS_UF_USE_DES_KEY_ONLY, 0x00200000): Used by the Kerberos protocol. This bit indicates that only des-cbc-md5 or des-cbc-crc keys, as defined in [RFC3961], are used in the Kerberos protocols for this account.
   */
  const ADS_UF_USE_DES_KEY_ONLY = 2097152;
  /**
   * @var int DR (ADS_UF_DONT_REQUIRE_PREAUTH, 0x00400000): Used by the Kerberos protocol. This bit indicates that the account is not required to present valid preauthentication data, as described in [RFC4120] section 7.5.2.
   */
  const ADS_UF_DONT_REQUIRE_PREAUTH = 4194304;
  /**
   * @var int PE (ADS_UF_PASSWORD_EXPIRED, 0x00800000): Specifies that the password age on the user has exceeded the maximum password age policy.
   */
  const ADS_UF_PASSWORD_EXPIRED = 8388608;
  /**
   * @var int TA (ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION, 0x01000000): Used by the Kerberos protocol. When set, this bit indicates that the account (when running as a service) obtains an S4U2self service ticket (as specified in [MS-SFU]) with the forwardable flag set. If this bit is cleared, the forwardable flag is not set in the S4U2self service ticket.
   */
  const ADS_UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 16777216;
  /**
   * @var int NA (ADS_UF_NO_AUTH_DATA_REQUIRED, 0x02000000): Used by the Kerberos protocol. This bit indicates that when the Key Distribution Center (KDC) is issuing a service ticket for this account, the Privilege Attribute Certificate (PAC) MUST NOT be included. For more information, see [RFC4120].
   */
  const ADS_UF_NO_AUTH_DATA_REQUIRED = 33554432;
  /**
   * @var int PS (ADS_UF_PARTIAL_SECRETS_ACCOUNT, 0x04000000): Specifies that the account is a computer account for a read-only domain controller (RODC). If this bit is set, the ADS_UF_WORKSTATION_TRUST_ACCOUNT must also be set. This flag is only interpreted by a DC whose DC functional level is DS_BEHAVIOR_WIN2008 or greater.
   */
  const ADS_UF_PARTIAL_SECRETS_ACCOUNT = 67108864;
}