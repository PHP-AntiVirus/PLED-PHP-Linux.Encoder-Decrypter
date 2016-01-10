#  PHP "Linux.Encoder" Decrypter (PLED script)

This is PHP fork of the decrypter CLI script for "Linux Encoder" ransomware malware.
Original Python version of the decrypter was written by [Bitdefender Labs Team](https://labs.bitdefender.com/2016/01/third-iteration-of-linux-ransomware-still-not-ready-for-prime-time/).

The inspiration for this tool is a growing number of websites being targeted with 
this nasty ransomware, leaving webmasters in despair. Initial idea was born while
discussing a solution of the encoded website on [Joomla Security subforum](http://forum.joomla.org/viewtopic.php?f=714&t=903398).
Since website owners most of the time don't have access to the shell command line, 
or Python is disabled in their hosting account, a browser oriented batch-execution 
version of the decrypter written in pure PHP is much more suitable for such purposes.


## Features:
* batch decryption mode
* PLANNED: single file & batch mode in command line (CLI)
* ... other ideas? Please contact me

## Usage
* upload to your web folder (browser execution), or any folder (command line execution)
* browser: open the URL which corresponds to the location of the PLED file


## Changelog
##### v1.0	[2016-01-10]
* added: target extension check
* added: option to define plain-text file extensions, only which will be cleaned from garbage
* added: PHP version check
* added: counter for files cleaned from garbage
* fixed: issue with remaining newline character in last 16 bytes
* improved: encrypter garbage cleanup function
* improved: extension check
* removed: erroneous variables

##### v1.0-RC2	[2016-01-09]
* added: encrypter garbage cleanup function
* added: stats tracking and printing
* fixed: problem with hex2bin() function not existing pre PHP 5.4.0
* fixed: disabled error reporting for notices and warning

##### v1.0-RC1	[2016-01-07]
* decrypter for Linux.Encoder version 3
* batch mode in-browser decryption


## TODO
* single-file decryption
* CLI mode
* other Linux.Encoder versions decoding ?
* batch encrypted files (re)moval
* ??? (send me suggestions)


## Original code source and author
All the credits for original decrypter algorithm go to the **Radu Caragea** from [Bitdefender Labs Team](https://labs.bitdefender.com/2016/01/third-iteration-of-linux-ransomware-still-not-ready-for-prime-time/).
Thank you Radu and the team, keep up the good work!


## PLED Author
Bernard Toplak bernard@php-antivirus.com
[www.php-antivirus.com](http://www.php-antivirus.com)

Be free to contact me if you need any assistance in decrypting the files, 
or don't have time, resources or knowledge to do it yourself.
