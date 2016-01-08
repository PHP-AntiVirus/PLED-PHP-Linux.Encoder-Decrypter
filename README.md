#  PHP "Linux.Encoder" Decrypter (PLED script)

This is PHP fork of the decrypter CLI script for "Linux Encoder" ransomware malware.
Original Python version of the decrypter was written by Bitdefender Labs Team [1]
(see below).

The inspiration for this tool is a growing number of websites being targeted with 
this nasty ransomware, leaving webmasters in despair. Initial idea was born while
discussing a solution of the encoded website on Joomla Security subforum [2].
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

v1.0-RC1	[2016-01-07]
* decrypter for Linux.Encoder version 3
* batch mode in-browser decryption


# TODO
* single-file decryption
* CLI mode
* stats and speed counters
* batch encrypted files (re)moval
* ??? (send me suggestions)


# Author
Bernard Toplak <bernard@php-antivirus.com>
www.php-antivirus.com [3]

## Original code source
All the credits for original decrypter algorithm go to the Bitdefender Labs Team [1]
Thank you girls & guys, keep up the good work!


## Links
[1] https://labs.bitdefender.com/2016/01/third-iteration-of-linux-ransomware-still-not-ready-for-prime-time/
[2] http://forum.joomla.org/viewtopic.php?f=714&t=903398
[3] http://www.php-antivirus.com