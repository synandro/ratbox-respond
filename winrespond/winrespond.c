/*
 *  winrespond.c: A challenge response generator for ircd-ratbox
 *
 *  Note: This is not compatible with previous versions of the CHALLENGE
 *  command, as the prior version was seriously flawed in many ways.
 * 
 *  Copyright (C) 2001 by the past and present ircd-hybrid developers.
 *  Copyright (C) 2005 Aaron Sethman <androsyn@ratbox.org> 
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *  $Id$
 *
 */

#include <stdio.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <windows.h>
#include "resource.h"

#define DOC_FILE	0
#define DOC_RSA		1
#define DOC_CHAL	2
#define DOC_DEC		3
#define DOC_GOOD        4

#define BUFSIZE		16384
#define REGBRANCH	"Software\\Hwy\\winrespond"

HINSTANCE hMainInstance;
HWND hMainWnd;
char g_Passphrase[BUFSIZE];
HWND TabArray[6];

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpszArgs, int nWinMode);
BOOL CALLBACK DialogFunc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam);
static UINT DoChallenge(char *, char *, char *, char *);
static void SaveRegistry(HWND hwnd);

int WINAPI WinMain(HINSTANCE hInstance,
                   HINSTANCE hPrevInstance,
                   PSTR szCmdLine,
                   int iCmdShow)
{
  int nRes;
  hMainInstance=hInstance;
  memset(g_Passphrase, '\0', BUFSIZE);
  nRes=DialogBox(hMainInstance, MAKEINTRESOURCE(IDD_DIALOG_MAIN), 0,
                 DialogFunc);
  return 0;
}

BOOL CALLBACK DialogFunc(HWND hwnd, UINT iMsg, WPARAM wParam, LPARAM lParam)
{
  switch(iMsg)
  {

    case WM_INITDIALOG:
    {
      HKEY hRegKey;
      hMainWnd=hwnd;
      SetClassLong(hwnd, GCL_HICON, (LONG)LoadIcon(hMainInstance,"winrespond"));
      if (RegOpenKey(HKEY_CURRENT_USER, REGBRANCH, &hRegKey) == ERROR_SUCCESS)
      {
        char dbuf[BUFSIZE];
        DWORD sdbuf = BUFSIZE;
        if (RegQueryValue(hRegKey, "keyfile", dbuf, &sdbuf) == ERROR_SUCCESS)
        {
          SetDlgItemText(hwnd, ID_KEY, dbuf);
        }
        RegCloseKey(hRegKey);
      }
      return TRUE;
    }

    case WM_COMMAND:
      /* WM_COMMAND messages are used for any button press */
      switch (LOWORD(wParam))
      {
        case ID_GEN:  /* Generate button */
        {
          char prvkey[BUFSIZE];
          char passphrase[BUFSIZE];
          char challenge[BUFSIZE];
          char response[BUFSIZE];

          UINT uRes = GetDlgItemText(hwnd, ID_KEY, prvkey, BUFSIZE - 1);
          if (uRes == 0)
          {
            SetDlgItemText(hwnd, ID_STATUS,
                           "Please Enter a Filename for the Key");
            return TRUE;
          }

          uRes = GetDlgItemText(hwnd, ID_CHAL, challenge, BUFSIZE - 1);
          if (uRes == 0)
          {
            SetDlgItemText(hwnd, ID_STATUS, "Please Enter a Challenge");
            return TRUE;
          }

          uRes = GetDlgItemText(hwnd, ID_PASS, passphrase, BUFSIZE - 1);
          if (uRes == 0)
          {
            SetDlgItemText(hwnd, ID_STATUS, "Using an empty passphrase");
            g_Passphrase[0] = '\0';
          }
          else
          {
            strcpy(g_Passphrase, passphrase);
          }

          uRes = DoChallenge(prvkey, passphrase, challenge, response);
          switch(uRes)
          {
            case DOC_FILE:
              SetDlgItemText(hwnd, ID_STATUS, "Please Enter a Valid Key File");
              return TRUE;

            case DOC_RSA:
              SetDlgItemText(hwnd, ID_STATUS,
                             "Unable to Read Private Key:  Passphrase?");
              return TRUE;
            case DOC_CHAL:
              SetDlgItemText(hwnd, ID_STATUS, "Bad Challenge");
              return TRUE;
            case DOC_DEC:
              SetDlgItemText(hwnd, ID_STATUS, "Decryption Error");
              return TRUE;
            case DOC_GOOD:
              SetDlgItemText(hwnd, ID_STATUS, "Response Sucessful");
              SetDlgItemText(hwnd, ID_RESP, response);
              return TRUE;
          }
          return TRUE;
        }

        case ID_OK:  /* Exit */
          SaveRegistry(hwnd);
          PostQuitMessage(0);
          return FALSE;

        default:
          return FALSE;
      }

    case WM_CLOSE: /* Catch the X or Close from the system menu */
      SaveRegistry(hwnd);
      PostQuitMessage(0);
      return FALSE;
  }
  /* Any unproccessed message in a dialog box is ignored */
  return FALSE;
}

static void SaveRegistry(HWND hwnd)
{
  HKEY hRegKey;
  char dbuf[BUFSIZE];
  UINT uRes;

  if (RegCreateKey(HKEY_CURRENT_USER, REGBRANCH, &hRegKey) == ERROR_SUCCESS)
  {
    uRes = GetDlgItemText(hwnd, ID_KEY, dbuf, BUFSIZE - 1);
    dbuf[BUFSIZE - 1] = '\0';
    if (uRes != 0)
      RegSetValue(hRegKey, "keyfile", REG_SZ, dbuf, BUFSIZE);
    else
      RegSetValue(hRegKey, "keyfile", REG_SZ, "", BUFSIZE);
    RegCloseKey(hRegKey);
  }
}

/* pass_cb is used by OpenSSL to obtain the passphrase.  On *NIX, it would
** do so by using a getpass().  In Windows, we look use what was obtained
** from the password text entry box.
*/
static int pass_cb(char *buf, int size, int rwflag, void *u)
{
	int len;
        char *tmp = g_Passphrase;
	if (tmp == NULL)
		return 0;
        len = strlen(tmp);
        if (len <= 0) 
		return 0;
        if (len > size)
        	len = size;
        memcpy(buf, tmp, len);
        return len;
}

static const char base64_table[] =
	{ 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
	  'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
	  'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
	  'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	  '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/', '\0'
	};

static const char base64_pad = '=';

static const short base64_reverse_table[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
	-1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
	-1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
};

unsigned char *
base64_encode(const unsigned char *str, int length)
{
	const unsigned char *current = str;
	unsigned char *p;
	unsigned char *result;

	if ((length + 2) < 0 || ((length + 2) / 3) >= (1 << (sizeof(int) * 8 - 2))) {
		return NULL;
	}

	result = malloc(((length + 2) / 3) * 4);
	p = result;

	while (length > 2) 
	{ 
		*p++ = base64_table[current[0] >> 2];
		*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
		*p++ = base64_table[((current[1] & 0x0f) << 2) + (current[2] >> 6)];
		*p++ = base64_table[current[2] & 0x3f];

		current += 3;
		length -= 3; 
	}

	if (length != 0) {
		*p++ = base64_table[current[0] >> 2];
		if (length > 1) {
			*p++ = base64_table[((current[0] & 0x03) << 4) + (current[1] >> 4)];
			*p++ = base64_table[(current[1] & 0x0f) << 2];
			*p++ = base64_pad;
		} else {
			*p++ = base64_table[(current[0] & 0x03) << 4];
			*p++ = base64_pad;
			*p++ = base64_pad;
		}
	}
	*p = '\0';
	return result;
}

unsigned char *
base64_decode(const unsigned char *str, int length, int *ret)
{
	const unsigned char *current = str;
	int ch, i = 0, j = 0, k;
	unsigned char *result;
	
	result = malloc(length + 1);

	while ((ch = *current++) != '\0' && length-- > 0) {
		if (ch == base64_pad) break;

		ch = base64_reverse_table[ch];
		if (ch < 0) continue;

		switch(i % 4) {
		case 0:
			result[j] = ch << 2;
			break;
		case 1:
			result[j++] |= ch >> 4;
			result[j] = (ch & 0x0f) << 4;
			break;
		case 2:
			result[j++] |= ch >>2;
			result[j] = (ch & 0x03) << 6;
			break;
		case 3:
			result[j++] |= ch;
			break;
		}
		i++;
	}

	k = j;

	if (ch == base64_pad) {
		switch(i % 4) {
		case 1:
			free(result);
			return NULL;
		case 2:
			k++;
		case 3:
			result[k++] = 0;
		}
	}
	result[j] = '\0';
	*ret = j;
	return result;
}


/* DOC_ constants are used to return status back to the Dialog box's
** callback routine (in order to display the proper error message to the
** "status" line.
*/
static UINT DoChallenge(char *prvkey, char *passphrase, char *challenge,
                        char *response)
{
	FILE *kfile;
	RSA *rsa = NULL;
	SHA256_CTX ctx;
	unsigned char *ndata, ddata[512];
	int len;

	if (!(kfile = fopen(prvkey, "r")))
		return DOC_FILE;
	
	SSLeay_add_all_ciphers();
	rsa = PEM_read_RSAPrivateKey(kfile, NULL,pass_cb, NULL);
  
	if(!rsa)
	{
		fclose(kfile);
		return DOC_RSA;
	}

	fclose(kfile);
	ndata = base64_decode((unsigned char *)challenge, strlen(challenge), &len);
	if (ndata == NULL)
		return DOC_CHAL;
	
	if (RSA_private_decrypt(len, (unsigned char*)ndata, (unsigned char*)ddata, rsa, RSA_PKCS1_OAEP_PADDING) == -1)
		return DOC_DEC;
	
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, (unsigned char *)ddata, len);
	SHA256_Final((unsigned char *)ddata, &ctx);
	ndata = base64_encode((unsigned char *)ddata, SHA256_DIGEST_LENGTH);
	strcpy(response, ndata);
	free(ndata);
	return DOC_GOOD;
}



