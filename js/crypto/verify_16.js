verify_16 = function() {};

verify_16.crypto_verify_16_ref_BYTES = 16;

verify_16.crypto_verify = function(x, xoffset, y)
{
	var differentbits = 0;
	
	for (var i = 0; i < 15; i++)
		differentbits |= (parseInt(x[xoffset + i] ^ y[i])) & 0xff;
	
	return (1 & ((parseInt(differentbits) - 1) >>> 8)) - 1;
};