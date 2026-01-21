/*
 *  respond.c: A challenge response generator for ircd-ratbox
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
#include <stdlib.h>
#include <string.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <unistd.h>

static int called_passcb = 0;
static int pass_cb(char *buf, int size, int rwflag, void *u)
{
	int len;
        char *tmp;

	called_passcb++;

        if(!isatty(fileno(stdin)))
	{
        	if(fgets(buf, size, stdin) == NULL)
        		return 0;
		tmp = strpbrk(buf, "\r\n");
		if(tmp != NULL)
			*tmp = '\0';
		return strlen(buf);
        }
	tmp = getpass("Enter passphrase for private key: ");
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

static unsigned char *
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

static unsigned char *
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

static unsigned char *
read_challenge(FILE *f)
{
	static unsigned char buf[16384];
	char *tmp;

	if(isatty(fileno(f)))
	{
		fprintf(stderr, "Please paste challenge text now\n");
	} else {
		if(!called_passcb)
		{
			/* throw away the unneeded password line */
			fgets((char *)buf, sizeof(buf), f);
		}
	}

        fgets((char *)buf, sizeof(buf), stdin);

	tmp = strpbrk((char *)buf, "\r\n");
	if(tmp != NULL)
		*tmp = '\0';

//	fread(buf, sizeof(buf), 1, f);
	return buf;
}


/* --- EVP-based RSA OAEP decrypt matching RSA_private_decrypt(...OAEP...) --- */
static int
rsa_oaep_decrypt_sha1(EVP_PKEY *pkey,
                      const unsigned char *in, size_t inlen,
                      unsigned char *out, size_t *outlen)
{
	int ok = 0;
	EVP_PKEY_CTX *ctx = NULL;
	size_t tmplen = 0;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if(ctx == NULL)
		goto done;

	if(EVP_PKEY_decrypt_init(ctx) <= 0)
		goto done;

	/* Match RSA_PKCS1_OAEP_PADDING behavior */
	if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
		goto done;

	/* Explicitly pin OAEP defaults to SHA-1 for wire-compatibility */
	if(EVP_PKEY_CTX_set_rsa_oaep_md(ctx, EVP_sha1()) <= 0)
		goto done;

	if(EVP_PKEY_CTX_set_rsa_mgf1_md(ctx, EVP_sha1()) <= 0)
		goto done;

	/* Determine required output length */
	if(EVP_PKEY_decrypt(ctx, NULL, &tmplen, in, inlen) <= 0)
		goto done;

	if(tmplen > *outlen)
		goto done;

	if(EVP_PKEY_decrypt(ctx, out, &tmplen, in, inlen) <= 0)
		goto done;

	*outlen = tmplen;
	ok = 1;

done:
	EVP_PKEY_CTX_free(ctx);
	return ok;
}

int
main(int argc, char **argv)
{
	FILE *kfile;
	EVP_PKEY *pkey = NULL;

	unsigned char *ptr;
	unsigned char *ndata = NULL;
	unsigned char *cipher = NULL;

	unsigned char ddata[512];           /* decrypted */
	unsigned char digest[EVP_MAX_MD_SIZE];
	unsigned int digest_len = 0;

	int clen = 0;

	if (argc < 2)
	{
		puts("Error: Usage: respond privatefile");
		return -1;
	}

	if (!(kfile = fopen(argv[1], "r")))
	{
		puts("Error: Could not open the private keyfile.");
		return -1;
	}

	/* Load private key using EVP */
	pkey = PEM_read_PrivateKey(kfile, NULL, pass_cb, NULL);
	fclose(kfile);

	if (pkey == NULL)
	{
		puts("Error: Could not read private key.");
		ERR_print_errors_fp(stderr);
		return -1;
	}

	/* Only RSA keys are valid for this protocol */
	if(EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA)
	{
		puts("Error: Private key is not RSA.");
		EVP_PKEY_free(pkey);
		return -1;
	}

	ptr = read_challenge(stdin);
	if(ptr == NULL)
	{
		puts("Error: Bad challenge.");
		EVP_PKEY_free(pkey);
		return -1;
	}

	cipher = base64_decode(ptr, (int)strlen((char *)ptr), &clen);
	if (cipher == NULL)
	{
		puts("Error: Bad challenge.");
		EVP_PKEY_free(pkey);
		return -1;
	}

	/* RSA OAEP decrypt */
	size_t outlen = sizeof(ddata);
	if(!rsa_oaep_decrypt_sha1(pkey, cipher, (size_t)clen, ddata, &outlen))
	{
		puts("Error: Decryption failed.");
		ERR_print_errors_fp(stderr);
		free(cipher);
		EVP_PKEY_free(pkey);
		return -1;
	}

	/* SHA1(decrypted_data) via EVP */
	if(EVP_Digest(ddata, outlen, digest, &digest_len, EVP_sha1(), NULL) != 1)
	{
		puts("Error: Digest failed.");
		ERR_print_errors_fp(stderr);
		free(cipher);
		EVP_PKEY_free(pkey);
		return -1;
	}

	ndata = base64_encode(digest, (int)digest_len);
	if(ndata == NULL)
	{
		puts("Error: Out of memory.");
		free(cipher);
		EVP_PKEY_free(pkey);
		return -1;
	}

	if(isatty(fileno(stdin)))
		fprintf(stderr, "Response: /quote CHALLENGE +");

	puts((char *)ndata);
	fflush(NULL);

	free(ndata);
	free(cipher);
	EVP_PKEY_free(pkey);
	return 0;
}

