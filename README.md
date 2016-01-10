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
* fixed: licensing data including with packages

##### v1.0-RC2	[2016-01-09]
* added: encrypter garbage cleanup function
* added: stats tracking and printing
* fixed: problem with hex2bin() function not existing pre PHP 5.4.0
* fixed: disabled error reporting for notices and warning

##### v1.0-RC1	[2016-01-07]
* decrypter for Linux.Encoder version 3
* batch mode in-browser decryption


## TODO
* Linux.Encoder.1 versions decryption ? ... send me 10 sample files encrypted with L.E.1
* single-file decryption
* CLI mode
* batch encrypted files (re)moval
* ??? (send me suggestions)


## Original source code author
All the credits for original decrypter algorithm go to the **Radu Caragea** from [Bitdefender Labs Team](https://labs.bitdefender.com/2016/01/third-iteration-of-linux-ransomware-still-not-ready-for-prime-time/).
Thank you Radu and the team, keep up the good work!


## PLED Author
Bernard Toplak bernard@php-antivirus.com
[www.php-antivirus.com](https://www.php-antivirus.com)

Be free to contact me if you need any assistance in decrypting the files, 
or don't have time, resources or knowledge to do it yourself.

## Licensing
    
    Copyright (c) 2016, Bernard Toplak
    License: GNU Affero General Public License, version 3 (AGPL-3.0)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
