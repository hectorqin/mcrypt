<?php

/**
 * mcrypt
 *
 * PHP 7.1 removed the mcrypt extension.
 *
 * PHP 4 >= 4.0.2, PHP 5, PHP 7 < 7.2.0, PECL mcrypt >= 1.0.0 .
 *
 * LICENSE: Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * @author    Hector qin <hectorqin@163.com>
 * @copyright 2018 Hector qin
 * @license   http://www.opensource.org/licenses/mit-license.html  MIT License
 * @link      https://github.com/hectorqin/mcrypt
 */

class Mcrypt{
    const PKCS5    = 'pkcs5padding';
    const PKCS7    = 'pkcs7padding';
    const ZERO     = 'zeropadding';
    const ISO10126 = 'iso10126';
    const ANSIX923 = 'ansix923';

    static $moduleList = null;
    static $modeList   = null;

    static $module  = null;
    static $mode    = null;
    static $padding = null;

    public static function getModuleList(){
        if(!extension_loaded('mcrypt')){
            throw new \Exception('Please install mcrypt extension .');
        }
        if(version_compare(PHP_VERSION, '7.2.0', '>=')){
            throw new \Exception('Only support PHP 4 >= 4.0.2, PHP 5, PHP 7 < 7.2.0, PECL mcrypt >= 1.0.0 .');
        }
        if(is_null(self::$moduleList)){
            self::$moduleList = mcrypt_list_algorithms();
        }
        return self::$moduleList;
    }

    public static function getModeList(){
        if(!extension_loaded('mcrypt')){
            throw new \Exception('Please install mcrypt extension .');
        }
        if(version_compare(PHP_VERSION, '7.2.0', '>=')){
            throw new \Exception('Only support PHP 4 >= 4.0.2, PHP 5, PHP 7 < 7.2.0, PECL mcrypt >= 1.0.0 .');
        }
        if(is_null(self::$modeList)){
            self::$modeList = mcrypt_list_modes();
        }
        return self::$modeList;
    }

    public static function setMode($module, $mode, $padding){
        if(!extension_loaded('mcrypt')){
            throw new \Exception('Please install mcrypt extension .');
        }
        if(version_compare(PHP_VERSION, '7.2.0', '>=')){
            throw new \Exception('Only support PHP 4 >= 4.0.2, PHP 5, PHP 7 < 7.2.0, PECL mcrypt >= 1.0.0 .');
        }
        if(is_null(self::$moduleList)){
            self::$moduleList = mcrypt_list_algorithms();
            self::$modeList   = mcrypt_list_modes();
        }
        if(!in_array($module, self::$moduleList)){
            return false;
        }
        if(!in_array($mode, self::$modeList)){
            return false;
        }
        self::$module  = $module;
        self::$mode    = $mode;
        self::$padding = $padding;
        return true;
    }

    /**
     *加密
     * @param <type> $value
     * @return <type>
     */
    public static function encrypt($value, $key, $iv=null, $base64=false){
        if(empty(self::$module)){
            return false;
        }
        $ivMaxSize = mcrypt_get_iv_size(self::$module, self::$mode);
        $ivSize = strlen($iv);
        if(is_null($iv)){
            $iv = mcrypt_create_iv($ivMaxSize, MCRYPT_DEV_RANDOM);
        }elseif($ivSize < $ivMaxSize){
            $iv .= str_repeat('0', $ivMaxSize - $ivSize);
        }elseif($ivSize > $ivMaxSize){
            $iv = substr($iv, 0, $ivMaxSize);
        }
        $value = self::paddingOrNot($value, true);
        $td = mcrypt_module_open(self::$module, '', self::$mode, '');
        mcrypt_generic_init($td, $key, $iv);
        $ret = mcrypt_generic($td, $value);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        return $base64? base64_encode($ret) : bin2hex($ret);
    }

    /**
     *解密
     * @param <type> $value
     * @return <type>
     */
    public static function decrypt($value, $key, $iv=null, $base64=false){
        if(empty(self::$module)){
            return false;
        }
        $ivMaxSize = mcrypt_get_iv_size(self::$module, self::$mode);
        $ivSize = strlen($iv);
        if(is_null($iv)){
            $iv = mcrypt_create_iv($ivMaxSize, MCRYPT_DEV_RANDOM);
        }elseif($ivSize < $ivMaxSize){
            $iv .= str_repeat('0', $ivMaxSize - $ivSize);
        }elseif($ivSize > $ivMaxSize){
            $iv = substr($iv, 0, $ivMaxSize);
        }
        $td = mcrypt_module_open(self::$module, '', self::$mode, '');
        mcrypt_generic_init($td, $key, $iv);
        $ret = trim(mdecrypt_generic($td, $base64? base64_decode($value) : hex2bin($value)));
        $ret = self::paddingOrNot($ret, false);
        mcrypt_generic_deinit($td);
        mcrypt_module_close($td);
        return $ret;
    }

    private static function paddingOrNot($data, $padding=true){
        $blockSize = mcrypt_get_block_size(self::$module, self::$mode);
        switch (self::$padding) {
            case self::PKCS5:
                return $padding ? self::paddingPKCS5($data, $blockSize) : self::unPaddingPKCS5($data);
            case self::PKCS7:
                return $padding ? self::paddingPKCS7($data, $blockSize) : self::unPaddingPKCS7($data);
            case self::ZERO:
                return $padding ? self::paddingZERO($data, $blockSize) : self::unPaddingZERO($data);
            case self::ISO10126:
                return $padding ? self::paddingISO10126($data, $blockSize) : self::unPaddingISO10126($data);
            case self::ANSIX923:
                return $padding ? self::paddingANSIX923($data, $blockSize) : self::unPaddingANSIX923($data);
            default:
                return $data;
        }
    }


    /**
    * 使用pkcs5Padding补齐字符串，块固定是8位
    * @param string $string
    * @param int $blockSize
    * @return string
    */
    private static function paddingPKCS5($string){
        $pad = 8 - (strlen($string) % 8);
        return $string . str_repeat(chr($pad), $pad);
    }

    /**
    * 删除pkcs5Padding补齐字符串
    * @param string $string
    * @return string
    */
    private static function unPaddingPKCS5($string){
        $pad = ord($string{strlen($string) - 1});
        if ($pad > strlen($string)) return false;
        if (strspn($string, chr($pad), strlen($string) - $pad) != $pad) return false;
        return substr($string, 0, -1 * $pad);
    }

    /**
    * 使用pkcs7Padding补齐字符串
    * @param string $string
    * @param int $blockSize
    * @return string
    */
    private static function paddingPKCS7($string, $blockSize){
        $pad = $blockSize - (strlen($string) % $blockSize);
        return $string . str_repeat(chr($pad), $pad);
    }

    /**
    * 删除pkcs7Padding补齐字符串
    * @param string $string
    * @return string
    */
    private static function unPaddingPKCS7($string){
        $pad = ord($string{strlen($string) - 1});
        if ($pad > strlen($string)) return false;
        if (strspn($string, chr($pad), strlen($string) - $pad) != $pad) return false;
        return substr($string, 0, -1 * $pad);
    }

    /**
    * 使用0补齐字符串
    * @param string $string
    * @param int $blockSize
    * @return string
    */
    private static function paddingZero($string, $blockSize){
        $pad = $blockSize - (strlen($string) % $blockSize);
        return $string . str_repeat(chr(0), $pad);
    }

    /**
    * 删除0补齐字符串
    * @param string $string
    * @return string
    */
    private static function unPaddingZero($string){
        return rtrim($string, chr(0));
    }

    /**
    * 使用ISO10126Padding补齐字符串
    * @param string $string
    * @param int $blockSize
    * @return string
    */
    private static function paddingISO10126($string, $blockSize){
        $pad = $blockSize - (strlen($string) % $blockSize);
        return $string . str_repeat(chr($pad), $pad);
    }

    /**
    * 删除ISO10126Padding补齐字符串
    * @param string $string
    * @return string
    */
    private static function unPaddingISO10126($string){
        $pad = ord($string{strlen($string) - 1});
        if ($pad > strlen($string)) return false;
        return substr($string, 0, -1 * $pad);
    }

    /**
    * 使用ANSIX923Padding补齐字符串
    * @param string $string
    * @param int $blockSize
    * @return string
    */
    private static function paddingANSIX923($string, $blockSize){
        $pad = $blockSize - (strlen($string) % $blockSize);
        return $string . str_repeat(chr(0), $pad-1) . chr($pad);
    }

    /**
    * 删除ANSIX923Padding补齐字符串
    * @param string $string
    * @return string
    */
    private static function unPaddingANSIX923($string){
        $pad = ord($string{strlen($string) - 1});
        if ($pad > strlen($string)) return false;
        return substr($string, 0, -1 * $pad);
    }
}