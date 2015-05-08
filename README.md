# Ldapper
__Ldapper__ is a PHP library built to streamline and simplify interactions with __Active Directory__ via __LDAP__ (Lightweight Directory Access Protocol).

Using Ldapper you can:
  *	search through AD using several filters and modifiers;
  *	create new and change existing users;
  *	modify UAC settings of said users;
  *	access groups and their properties;
  *	name map X.509 certificates for user authentication purposes.

## Structure
Ldapper consists of several classes spread about several files. You must include only the `ldapper.php`, others will come bundled.

Code-wise everything is inside a namespace `Ldapper`:
  *	`DirectoryManager` is the main class, responsible for controlling all operations;
  * `DirectoryObject` is the object representation of a generic Active Directory object;
  *	`DirectoryUser` is a subclass of the `DirectoryObject` that represents a user;
  *	`DirectoryGroup` is a subclass of the `DirectoryObject` that represents a group;
  *	`DirectoryHelper` is a set of additional static functions; 
  *	`DirectoryUAC` is an enumeration of user access control (UAC) settings.

Code itself is very well documented and can be used for future reference.

## Usage
### Connection
Information needed to connect to an Active Directory via LDAP includes server URI, user account credentials, as well as several paths inside a controller forest.

Server URI can be provided either by an array `array( 'host' => ' ', 'port' => ' ' )`, or by a string qualified for `parse_url()`. It is important to provide a protocol scheme and a correctly corresponding port. In PHP it is valid to have `ldap://` as well as `ldaps://` protocols, later being purely fictional and  meaning LDAP over SSL. Default ports are 389 for `ldap://` and 636 for `ldaps://`.

It is important to remember, that you need an "over SSL" option to perform any data changing operations (with proper domain administrator credentials). Web-servers must be prepared as well with domain controller's keys and certificates located on their drives.

To properly use LDAP and Ldapper you need to have and understanding of basic directory units such as object's Common Name, Distinguished Name, Organizational Unit. Having such knowledge you must provide a base path to the root of directory (a basis for every Distinguished Name), a path to a node with groups and a path of a node that will be selected immediately after the connection is established. Both of the later are relative to base path.   

Using JSON-like syntax all needed information can be demonstrated as such:
```json
  {
    "server":     { "host": "ldaps://server", "port": "636" },
    "domain":     "DOMAIN",
    "base_dn":    "DC=DomainForest,DC=local",
    "groups_cn":  "CN=Users",
    "default_ou": "OU=unit",
    "user":       "username",
    "password":   "password"
  }
```

And then the connection is established like this:
```php
$dm = new DirectoryManager(array( 'host' => 'server.host', 'port' => 'server.port' ), 'base_dn', 'groups_cn', 'default_ou');
if ($dm->hasConnection() && $dm->open('user', 'password')) {
  // successfully connected
} else {
  // connection failed
}
```
  
The following LDAP options are used to set up the connection:
```
LDAP_OPT_PROTOCOL_VERSION = 3
LDAP_OPT_REFERRALS = 0
LDAP_OPT_SIZELIMIT = 1000
```

### User management
It is possible to search for, get, create and modify users. 

#### Search for users
You can search for users with any available attribute present in your Active Directory. Several methods of comparison are supported for search filters:
  *	__equal__, __=__ - exactly equal;
  *	__not__, __!=__, __<>__ - exactly not equal
  *	__like__, __~=__ - substring match (both sides);
  *	__gt__, __>__ - exactly greater than;
  *	__gte__, __>=__ - greater than or equal;
  *	__lt__, __<__ - exactly lesser than;
  *	__lte__, __<=__ - lesser than or equal;
  
For example:
```php
$filters = array();
$filters[] = array('objectclass', 'user', '=');
$filters[] = array('cn', $user_rdn, 'like');
$users = $dm->findUsers($filters);
```

The result of the search is an array, however what it contains may vary. By default it consists of usernames, but you can specify a flag that will instead force it to return full DirectoryUser objects. This will be much slower. To counter such effect you can as well specify a set of attributes to be fetched when searching. You will usually need very specific attributes, and it can positively and significantly impact the performance. 

#### Get a user
When you have a distinguished or a relative distinguished name of a user, you can get it's object representation.
```php
$dm->getUser($user_rdn);
```

Here you can limit attribute set again, making it faster to fetch and create.

#### Create a user
User creating is minimalistic. You simply provide username and password and in return receive an object. Several attributes will be set up automatically: cn, givenName, displayName, sn, objectclass, sAMAccountName, userPrincipalName, unicodePwd, userAccountControl. UAC settings are set to `ADS_UF_DONT_EXPIRE_PASSWD | ADS_UF_NORMAL_ACCOUNT` by default.
```php
$dm->addUser($user_name, $user_pass);
```

Every action above (searching, getting and creating) can be adjusted by one common argument: path. If provided and not empty, it will override the current path and perform an action relative to it. If there is no such a path, an error will generate.

#### Modify a user
After user object is received, it is possible to modify it using common and specific actions. Specific actions include enabling/disabling an account, changing password and name mapping an X.509 certificate. Every attribute can be changed sub-manually as well via a common method. It is not impossible to modify changeset directly, however it is important to remember naming convention and to have proper encoding.
 
In a similar manner you can access existing user data (the one that was fetched, obviously). Some data, such as password, is encrypted and therefore cannot be accessed. When accessing any data you have an option whether to account for changes or ignore them.

Changes are not immediately "commited" or "saved" to your Active Directory as you go. It is important to explicitly call for `$dm->modUser()` function. Yes, it is a part of `DirectoryManager` class.

Here is an example where we name map a certificate that was just uploaded:
```php
$user = $dm->getUser($user_rdn);
if ($user) {
  if ($user->mapX509($_FILES['file']['tmp_name'])) {
    if (!$dm->modUser($user)) {
      // error
    }
    // success
  } else {
    // error
  }
}
```

You are free to call any number of object modifying function before finally saving the changes. Saving can be performed in three distinctive ways:
  * You can add the changeset to whatever is already stored in your directory.
  * You can update existing data with this changeset (default behavior).
  * Or, you can delete provided data from your directory.

Major limitation of LDAP is that it supports only one encoding — UTF-8. That is not bad on it's own, however you need to keep it in mind when working with raw data. All Ldapper methods do necessary conversions automatically. Use `DirectoryManager::$inputEncoding` and `DirectoryManager::$outputEncoding` to set up them to your environment.

### Group management
It is possible to get and modify groups, similar to user management. However, modifications are limited to user manipulations inside a group. Everything else is not implemented at the moment.

### Test user authorization
Similarly to connection it is possible to test user authorization in Active Directory by calling `$dm->open()` with username and password. It will change, however, currently bound user and thus operation permissions.

### Error handling
There are two kinds of errors in Ldapper. Constructors can throw exceptions in several documented cases. Otherwise, you must check if a function returned a boolean FALSE, and then get a read-only `$dm->lastError` variable. It contains the most recent error message, whether it is an internal error or LDAP extension error.
