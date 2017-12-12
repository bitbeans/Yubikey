# Yubikey

Yubikey for Laravel 5

This package is based on the [Laravel 4 package](https://github.com/Monarobase/Yubikey) by Monarobase.


[Buy a Yubikey](https://store.yubico.com)

[Yubico API Key Generator](https://upgrade.yubico.com/getapikey/)


## Installation

Add `bitbeans/yubikey` to `composer.json`.
```
"bitbeans/yubikey": "dev-master"
```

Run `composer update` to pull down the latest version of Yubikey.

Now open up `PROJECTFOLDER/config/app.php` and add the service provider to your `providers` array.
```php
'providers' => [
    ...
	Bitbeans\Yubikey\YubikeyServiceProvider::class,
]
```

And also the alias.
```php
'aliases' => [
    ...
	'Yubikey' => Bitbeans\Yubikey\YubikeyFacade::class,
]
```

You can easily integrate the Yubikey Verification into your authentication system in two steps :
- Add a field (eg `yubikey_identity`) in your user table
- now check your user with username/email + password + yubikey_identity


## Configuration

Run `php artisan vendor:publish` and modify the config file (PROJECTFOLDER/config/yubikey.php) with your own information.


## Example

```php
use YubiKey;

try
{
	$yubikey_auth = Yubikey::verify(Input::get('otp'));
	$yubikey_params = Yubikey::getParameters();
	$yubikey_identity = Yubikey::getParameter('identity');
}
catch (\Exception $e)
{
	$error = $e->getMessage();
}
```
