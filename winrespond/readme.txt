RSA Respond for Windows

This is a Windows GUI port of the ircd-ratbox RSA Respond tool.

This is used for the ircd-ratbox challenge/response oper
system, to generate the response for the server's challenge.

The port requires an RSA key pair(1)

Run the winrespond.exe program, type in your private key's
filename, the challenge text received from the server, and
the passphrase for the key, then hit the Generate button.

The response text can then be copied and pasted back to the
server.

WinRespond now stores the last used key file name in the registry,
under HKEY_CURRENT_USER\Software\Hwy\winrespond.  This branch
of the registry should be deleted when the program is no longer
needed.

(1) A Keypair can be generated at a Cygwin prompt or on any
    UNIX system with OpenSSL installed with the following
    set of commands:

  openssl genrsa -des3 -out rsa.key 1024
  openssl rsa -in rsa.key -pubout -out rsa.pub

Notes:  A passphrase is recommended but not required.

Credits:  Concept by desrt and David-T
          UNIX Code by Androsyn and A1kmm
          Windows Specific code by Hwy
            with help and suggestions
            from screwedup and pheromone

	  New variant for ircd-ratbox and mingw32 port by
	  Aaron Sethman <androsyn@ratbox.org>

Building Yourself:  You need a current Cygwin or mingw32 installed, 
with the OpenSSL libraries and development package.

Run make
To pare down the size of the binary, run 'strip winrespond.exe'

# $Id$
