<?php
/**
 * PHP "Linux.Encoder" Decrypter - PLED
 * @version 1.0.BETA
 *
 * @author Bernard Toplak <bernard@php-antivirus.com>
 * @link http://www.php-antivirus.com
 * @link http://gitlab.com/btoplak
 *
 * For MORE INFORMATION about this script please check README file
 *
 * 
 * @license GNU Public License, version 3 (GPL-3.0)
 * http://opensource.org/licenses/gpl-3.0.html
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 */

/* * * * * * * * * * * * * * *  SETTINGS  * * * * * * * * * * * * * * */
ini_set('max_execution_time', '0'); // supress problems with timeouts
ini_set('set_time_limit', '0'); // supress problems with timeouts
#ini_set('display_errors', '0'); // show/hide errors
ini_set('output_buffering', '0'); // disable output buffering
ini_set('implicit_flush', '1'); // disable output buffering
ignore_user_abort(true);

$ignoreDirFiles = array('.','..','.DS_Store','.svn','.git','README.md'); // dirs/files to ignore
$encryptedExtension = '.encrypted';
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

while ($dir4scan) {
    $thisDir = array_pop($dir4scan);
    if ($dirContent = scandir($thisDir)) {
        foreach ($dirContent As $content) {
            if (!in_array($content, $ignoreDirFiles)) {
                $thisFile = "$thisDir/$content";
                if (is_file($thisFile)) {
                    if (substr($thisFile, -strlen($encryptedExtension)) === $encryptedExtension)
                        decrypt_file($thisFile);
                } else {
                    $dir4scan[] = $thisFile;
                    mkdir($targetDir.DIRECTORY_SEPARATOR.$thisFile, 0755, true);
                }
            }
        }
    }
}

smart_echo("Congratulations, PLED has decrypted your files succesfully!\n");
smart_echo("Because of a bug in the encryption, the output files might contain 16 random bytes at the end");


function decrypt_file($filePath) {
    global $encryptedExtension;
    global $targetDir;

    $decryptedFilePath = $targetDir.DIRECTORY_SEPARATOR.mb_substr($filePath, 2, -strlen($encryptedExtension));
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
    
    $RSAenc = fread($encFileHandle, 256);
    $IV = fread($encFileHandle, 16);
    $AESkey = $IV."\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    $padding = ord($IV[15]) & 0x0F;
    
    $prev = $IV;
    $written = 0;
    while (true) {
            $ciphertext = fread($encFileHandle, 32);
            if(!$ciphertext)
                break;
            $decripted = mcrypt_decrypt(MCRYPT_RIJNDAEL_128,$AESkey,$ciphertext,MCRYPT_MODE_CBC,$prev);
            fwrite($decFileHandle, $decripted);
            $written += 32;
            $prev = mb_substr($ciphertext, 0, 16);
    }
    
    if ($padding != 0)
        ftruncate($decFileHandle, $written - (16 - $padding));

    smart_echo('File '.$decryptedFilePath." successfuly decrypted.\n");
}

function smart_echo($string){
    if(php_sapi_name() === 'cli') { # CLI mode
        echo $string;
    } else { # HTML mode
        echo nl2br($string);
    }
}