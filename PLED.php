<?php
/**
 * PHP "Linux.Encoder" Decrypter - PLED
 *
 * @author Bernard Toplak <bernard@php-antivirus.com>
 * @author Radu Caragea, Bitdefender https://labs.bitdefender.com/
 * 
 * @link https://www.php-antivirus.com/
 * @link https://github.com/PHP-AntiVirus/
 *
 * For MORE INFORMATION about this script please check the README file
 *
 * @copyright (c) 2016, Bernard Toplak
 * 
 * @license GNU Affero General Public License, version 3 (AGPL-3.0)
 * http://www.gnu.org/licenses/agpl.txt
 * 
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.

 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* * * * * * * * * * * * * * *  SETTINGS  * * * * * * * * * * * * * * */
ini_set('max_execution_time', '600'); // supress problems with timeouts
ini_set('set_time_limit', '600'); // supress problems with timeouts
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
ini_set('output_buffering', '0'); // disable output buffering
ini_set('implicit_flush', '1'); // disable output buffering

$version = '1.1';

$ignoreDirFiles = array('.','..','.DS_Store','.svn','.git','README.md'); // dirs/files to ignore
$encryptedExtension = 'encrypted'; // extension of the encrypted files
$plaintextExtensions = array('php','txt','js','css','htm','html','ini'); // for which files to fix last garbage bytes
$dir4scan = array('.'); // a directory to scan; default: current dir
$targetDir = 'PLED_decrypted';
/* * * * * * * * * * * * * *  END SETTINGS  * * * * * * * * * * * * * * */

/*
 * sanity checks
 */
if (!extension_loaded('mbstring'))
    die ('PHP Extension "mbstring" not loaded');
if (!extension_loaded('mcrypt'))
    die ('PHP Extension "mcrypt" not loaded');

if (version_compare(PHP_VERSION, '5.3.0', '<')) {
die( 'You are using PHP Version: '. PHP_VERSION .'. You have to deploy at least PHP 5.3.0 to be able to use this script!');
}

/* * * * * * * * * * * * * *  FUNCTIONS  * * * * * * * * * * * * * * */

if ( !function_exists( 'hex2bin' ) ) { # exists only in PHP > 5.4
    function hex2bin( $str ) {
        $sbin = "";
        $len = strlen( $str );
        for ( $i = 0; $i < $len; $i += 2 ) {
            $sbin .= pack( "H*", substr( $str, $i, 2 ) );
        }
        return $sbin;
    }
}

function decrypt_file($filePath) {
    global $encryptedExtension;
    global $targetDir;
    global $plaintextExtensions;
    global $filesCleanedCount;

    $decryptedFilePath = $targetDir.'/'.mb_substr($filePath, 2, -strlen($encryptedExtension)-1);
    
    if (file_exists($decryptedFilePath)) {
        smart_echo("File $decryptedFilePath already exists, skipping to the next one ...\n");
        return false;
    }
    $decFileHandle = fopen($decryptedFilePath, 'w');
    
    $encFileHandle = fopen($filePath, 'r');
    $signature = fread($encFileHandle, 4);
    if($signature !== hex2bin('00010000')) {
        smart_echo("File $decryptedFilePath isn\'t encrypted with Linux.Encoder.3, skipping\n");
        return false;
    }
    
    // $RSAenc = fread($encFileHandle, 256); # unused, to be removed
    fseek($encFileHandle, 256, SEEK_CUR);
    $IV = fread($encFileHandle, 16);
    $AESkey = $IV."\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    $padding = ord($IV[15]) & 0x0F;
    $written = 0;
    
    while (true) {
            $ciphertext = fread($encFileHandle, 32);
            if(!$ciphertext)
            {
                $last_bytes = $decrypted;
                break;
            }
            $decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128,$AESkey,$ciphertext,MCRYPT_MODE_CBC,$IV);
            fwrite($decFileHandle, $decrypted);
            $written += 32;
            $IV = mb_substr($ciphertext, 0, 16);
    }
    
    $targetExtension = end(explode('.',$decryptedFilePath));
    if ($padding != 0 && in_array($targetExtension, $plaintextExtensions)) {
         smart_echo('['.date('y-m-d h:i:s')."] .. $decryptedFilePath will be cleaned from garbage bytes.\n");
         # copy($decryptedFilePath, $decryptedFilePath.'.raw');
         $filesCleanedCount += 1;
         washmachine($decFileHandle, $written, $padding, $last_bytes);
    }

    fclose ($decFileHandle);
    fclose ($encFileHandle);
    
    smart_echo('['.date('y-m-d h:i:s')."] .. $decryptedFilePath successfuly decrypted.\n");
}


function washmachine($decFileHandle, $written, $padding, $last_bytes) {
    $correction = 0;
    $truncated_lines = substr($last_bytes, 0, -(16 - $padding) );
    # check if last char is a newline
    if (substr($truncated_lines, -1, 1) == "\x0A" ) {
        $truncated_lines = substr($truncated_lines, 0, -1);
        $correction += 1;
    }
    # check if last 16 bytes are printable
    if (strlen($truncated_lines) >= 16) {
        $last_16 = substr($truncated_lines,-16,16);
        $line_printable = ctype_print($last_16);
        if (!$line_printable) 
            $correction += 16;
    }
    ftruncate($decFileHandle, $written -(16 + $correction - $padding));    
}


function smart_echo($string){
    if (php_sapi_name() === 'cli') { # CLI mode
        echo $string;
    } else { # HTML mode
        echo nl2br($string);
    }
}


$fileCount = $fileEncCount = $folderCount = $sumSize = 0;
$start = microtime(1);
while ($dir4scan) {
    $thisDir = array_pop($dir4scan);
    if ($dirContent = scandir($thisDir)) {
        foreach ($dirContent As $content) {
            if (!in_array($content, $ignoreDirFiles)) {
                $thisFile = "$thisDir/$content";
                $fileInfo = pathinfo($thisFile);
                if (is_file($thisFile)) {
                    $fileCount +=1;
                    $sumSize += filesize($thisFile);
                    if ($fileInfo['extension'] === $encryptedExtension) {
                        $fileEncCount +=1;
                        decrypt_file($thisFile);
                    }
                } else {
                    $folderCount +=1;
                    $dir4scan[] = $thisFile;
                    mkdir($targetDir.'/'.$thisFile, 0755, true);
                }
            }
        }
    }
}
$end = microtime(1);
$runTime = $end - $start;

echo '<pre>';
echo str_repeat('-', 70)."\n";
smart_echo(str_pad('|  Folders scanned : '.$folderCount, 70)."|\n");
smart_echo(str_pad('|  Files scanned : '.$fileCount, 70)."|\n");
smart_echo(str_pad('|  Scanned size : '.round($sumSize/1024,2).' kB', 70)."|\n");
smart_echo(str_pad('|  Scanning time : '.round($runTime,2).' sec', 70)."|\n");
smart_echo(str_pad('|  Scan speed : '.round($sumSize/1024/$runTime, 2).' kB/sec   ||   '.round($fileCount/$runTime, 2).' files/sec', 70)."|\n");
echo str_repeat('-', 70)."\n";
smart_echo(str_pad('|  Files decrypted : '.$fileEncCount, 70)."|\n");
smart_echo(str_pad('|  Files with garbage cleaned : '.$filesCleanedCount, 70)."|\n");
smart_echo(str_pad('|  Decrypt speed : '.round($sumSize/1024/$runTime, 2).' kB/sec   ||   '.round($fileEncCount/$runTime, 2).' files/sec', 70)."|\n");
echo str_repeat('-', 70)."\n";
smart_echo('['.date('y-m-d h:i:s')."] .... Congratulations, PLED has decrypted your files succesfully!\n");
smart_echo(str_repeat('-', 70)."\n");
smart_echo(<<<LICENSE
PLED script $version - Copyright (C) 2016  Bernard Toplak
This program comes with ABSOLUTELY NO WARRANTY;
This is free software, and you are welcome to redistribute it 
under certain conditions;

LICENSE
);
smart_echo(str_repeat('-', 70)."\n");
echo '</pre>';