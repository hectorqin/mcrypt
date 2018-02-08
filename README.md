# mcrypt

A simple class for performing AES encryption with mcrypt.

In general, support all module and mode of the mcrypt extension.

## Usage

```
require_once 'Mcrypt.php';
$string = 'test';
$key = '1234567812345678';

// AES/ECB/PKCS5Padding
Mcrypt::setMode(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, Mcrypt::PKCS5);
$encryptedString = Mcrypt::encrypt($string, $key);
$decryptedString = Mcrypt::decrypt($encryptedString, $key);
echo $string, "   ", $encryptedString, "   ", $decryptedString, "\n";

// AES/ECB/PKCS7Padding
Mcrypt::setMode(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, Mcrypt::PKCS7);
$encryptedString = Mcrypt::encrypt($string, $key);
$decryptedString = Mcrypt::decrypt($encryptedString, $key);
echo $string, "   ", $encryptedString, "   ", $decryptedString, "\n";


// AES/ECB/ZEROPadding
Mcrypt::setMode(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, Mcrypt::ZERO);
$encryptedString = Mcrypt::encrypt($string, $key);
$decryptedString = Mcrypt::decrypt($encryptedString, $key);
echo $string, "   ", $encryptedString, "   ", $decryptedString, "\n";


// AES/ECB/ISO10126Padding
Mcrypt::setMode(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, Mcrypt::ISO10126);
$encryptedString = Mcrypt::encrypt($string, $key);
$decryptedString = Mcrypt::decrypt($encryptedString, $key);
echo $string, "   ", $encryptedString, "   ", $decryptedString, "\n";


// AES/ECB/ANSIX923Padding
Mcrypt::setMode(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB, Mcrypt::ANSIX923);
$encryptedString = Mcrypt::encrypt($string, $key);
$decryptedString = Mcrypt::decrypt($encryptedString, $key);
echo $string, "   ", $encryptedString, "   ", $decryptedString, "\n";

```

## LICENSE

MIT