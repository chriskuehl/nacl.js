xsalsa20poly1305 = function() {};

xsalsa20poly1305.crypto_secretbox_KEYBYTES = 32;
xsalsa20poly1305.crypto_secretbox_NONCEBYTES = 24;
xsalsa20poly1305.crypto_secretbox_ZEROBYTES = 32;
xsalsa20poly1305.crypto_secretbox_BOXZEROBYTES = 16;

xsalsa20poly1305.crypto_secretbox = function(c, m, mlen, n, k)
{
	if (mlen < 32)
		return -1;

	xsalsa20.crypto_stream_xor(c, m, mlen, n, k);
	poly1305.crypto_onetimeauth(c, 16, c, 32, mlen - 32, c);
	
	for (var i = 0; i < 16; ++i)
		c[i] = 0;
	
	return 0;
}

xsalsa20poly1305.crypto_secretbox_open = function(m, c, clen, n, k)
{
	if (clen < 32)
		return -1;

	var subkeyp = new Array(32);
	
	xsalsa20.crypto_stream(subkeyp, 32, n, k);
	
	if (poly1305.crypto_onetimeauth_verify(c, 16, c, 32, clen - 32, subkeyp) != 0)
		return -1;
	
	xsalsa20.crypto_stream_xor(m, c, clen, n, k);
	
	for (var i = 0; i < 32; ++i)
		m[i] = 0;
	
	return 0;
}