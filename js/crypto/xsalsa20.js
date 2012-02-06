xsalsa20 = function() {};

xsalsa20.crypto_stream_xsalsa20_ref_KEYBYTES = 32;
xsalsa20.crypto_stream_xsalsa20_ref_NONCEBYTES = 24;
	
xsalsa20.sigma = stringToBytes("expand 32-byte k");
					/* {(byte) 'e', (byte) 'x', (byte) 'p', (byte) 'a',
					  (byte) 'n', (byte) 'd', (byte) ' ', (byte) '3',
					  (byte) '2', (byte) '-', (byte) 'b', (byte) 'y',
					  (byte) 't', (byte) 'e', (byte) ' ', (byte) 'k'}; */
	
xsalsa20.crypto_stream = function(c, clen, n, k)
{
	var subkey = new Array(32);
	
	hsalsa20.crypto_core(subkey, n, k, sigma);
	return salsa20.crypto_stream(c, clen, n, 16, subkey);
};

xsalsa20.crypto_stream_xor = function(c, m, mlen, n, k)
{
	var subkey = new Array(32);
	
	hsalsa20.crypto_core(subkey, n, k, sigma);
	return salsa20.crypto_stream_xor(c, m, parseInt(mlen), n, 16, subkey);
};