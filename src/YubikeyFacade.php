<?php
 /*
 * This file is based on Monarobase-Yubikey (Laravel 4).
 * And was modified for Laravel 5 compatibility.
 *
 * (c) 2015 Christian Hermann
 * (c) 2013 Monarobase
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 *
 *
 * @author    Monarobase
 * @author    Christian Hermann
 * @package     Yubikey
 * @copyright   (c) 2013 Monarobase <jonathan@monarobase.net> 
 *              (c) 2015 Chistian Hermann <c.hermann@bitbeans.de>
 * @link        http://monarobase.net
 * @link        https://github.com/bitbeans
 */

namespace Bitbeans\Yubikey;

use Illuminate\Support\Facades\Facade;

class YubikeyFacade extends Facade {

	/**
	 * Get the registered name of the component.
	 *
	 * @return string
	 */
	protected static function getFacadeAccessor() { return 'yubikey'; }

}