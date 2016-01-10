<?php
/**
 * PHP "Linux.Encoder" Decrypter - PLED
 * @version 1.0-RC3
 *
 * @author Bernard Toplak <bernard@php-antivirus.com>
 * @link http://www.php-antivirus.com
 * @link http://gitlab.com/btoplak
 *
 * For MORE INFORMATION about this script please check README file
 *
 * 
 * @license GNU Affero Public License, version 3 (AGPL-3.0)
 * http://opensource.org/licenses/agpl-3.0.html
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for
 * more details.
 *
 */

/* * * * * * * * * * * * * * *  SETTINGS  * * * * * * * * * * * * * * */
ini_set('max_execution_time', '120'); // supress problems with timeouts
ini_set('set_time_limit', '120'); // supress problems with timeouts
error_reporting(E_ALL & ~E_NOTICE & ~E_WARNING);
ini_set('output_buffering', '0'); // disable output buffering
ini_set('implicit_flush', '1'); // disable output buffering


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
         smart_echo("File $decryptedFilePath will be cleaned from garbage bytes.\n");
         # copy($decryptedFilePath, $decryptedFilePath.'.raw');
         $filesCleanedCount += 1;
         washmachine($decFileHandle, $written, $padding, $last_bytes);
    }

    fclose ($decFileHandle);
    fclose ($encFileHandle);
    
    smart_echo("File $decryptedFilePath successfuly decrypted.\n");
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
$start = microtime();
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
$end = microtime();
$runTime = $end - $start;

echo '<pre>';
echo str_repeat('-', 50)."\n";
smart_echo(str_pad('|  Folders scanned : '.$folderCount, 50)."|\n");
smart_echo(str_pad('|  Files scanned : '.$fileCount, 50)."|\n");
smart_echo(str_pad('|  Files decrypted : '.$fileEncCount, 50)."|\n");
smart_echo(str_pad('|  Files with garbage cleaned : '.$filesCleanedCount, 50)."|\n");
smart_echo(str_pad('|  Scanned size : '.round($sumSize/1024,2).' kB', 50)."|\n");
smart_echo(str_pad('|  Scanning time : '.round($runTime,2).' sec', 50)."|\n");
smart_echo(str_pad('|  Speed : '.round($fileCount/$runTime, 2).' files/sec || '.round($sumSize/1024/$runTime, 2).' kB/sec', 50)."|\n");
echo str_repeat('-', 50)."\n";
echo '</pre>';

smart_echo("Congratulations, PLED has decrypted your files succesfully!\n");
smart_echo("Because of a bug in the encryption the output files might still contain 16 random bytes at the end.\nPlease check your files.");

