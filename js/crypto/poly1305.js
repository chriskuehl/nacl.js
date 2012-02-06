poly1305 = function() {};

poly1305.CRYPTO_BYTES = 16;
poly1305.CRYPTO_KEYBYTES = 32;
	
poly1305.minusp = [5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252];

poly1305.crypto_onetimeauth_verify = function(h, hoffset, inv, invoffset, inlen, k)
{
	var correct = new Array(16);
	
	this.crypto_onetimeauth(correct, 0, inv, invoffset, inlen, k);
	return verify_16.crypto_verify(h, hoffset, correct);
};

poly1305.add = function(h, c)
{
	var j;
	var u = 0;
	
	for (j = 0; j < 17; ++j)
	{
		u += h[j] + c[j];
		h[j] = u & 255;
		u >>>= 8;
	}
};

poly1305.squeeze = function(h)
{
	var u = 0;
	
	for (var j = 0; j < 16; ++j)
	{
		u += h[j]; 
		h[j] = u & 255; 
		u >>>= 8;
	}
	
	u += h[16];
	h[16] = u & 3;
	u = 5 * (u >>> 2);
	
	for (var j = 0; j < 16; ++j)
	{
		u += h[j];
		h[j] = u & 255;
		u >>>= 8;
	}
	
	u += h[16];
	h[16] = u;
};

poly1305.freeze = function(h)
{
	var horig = new Array(17);
	
	for (var j = 0; j < 17; ++j)
		horig[j] = h[j];
	
	this.add(h, minusp);
	
	var negative = parseInt(-(h[16] >>> 7));
	
	for (var j = 0; j < 17; ++j)
		h[j] ^= negative & (horig[j] ^ h[j]);
};

poly1305.mulmod = function(h, r)
{
	var hr = new Array(17);
	
	for (var i = 0; i < 17; ++i)
	{
		var u = 0;
		
		for (var j = 0; j <= i; ++j) 
			u += h[j] * r[i - j];
		
		for (var j = i + 1; j < 17; ++j) 
			u += 320 * h[j] * r[i + 17 - j];
		
		hr[i] = u;
	}
	
	for (var i = 0; i < 17; ++i)
		h[i] = hr[i];
	
	this.squeeze(h);
};

poly1305.crypto_onetimeauth = function(outv, outvoffset, inv, invoffset, inlen, k)
{
	var j;
	var r = new Array(17);
	var h = new Array(17);
	var c = new Array(17);

	r[0] = k[0] & 0xFF;
	r[1] = k[1] & 0xFF;
	r[2] = k[2] & 0xFF;
	r[3] = k[3] & 15;
	r[4] = k[4] & 252;
	r[5] = k[5] & 0xFF;
	r[6] = k[6] & 0xFF;
	r[7] = k[7] & 15;
	r[8] = k[8] & 252;
	r[9] = k[9] & 0xFF;
	r[10] = k[10] & 0xFF;
	r[11] = k[11] & 15;
	r[12] = k[12] & 252;
	r[13] = k[13] & 0xFF;
	r[14] = k[14] & 0xFF;
	r[15] = k[15] & 15;
	r[16] = 0;

	for (j = 0; j < 17; ++j)
		h[j] = 0;

	while (inlen > 0)
	{
		for (j = 0; j < 17; ++j)
			c[j] = 0;
		
		for (j = 0; (j < 16) && (j < inlen); ++j)
			c[j] = inv[invoffset + j]&0xff;
		
		c[j] = 1;
		invoffset += j;
		inlen -= j;
		this.add(h, c);
		this.mulmod(h, r);
	}

	this.freeze(h);

	for (j = 0; j < 16; ++j) 
		c[j] = k[j + 16] & 0xFF;
	
	c[16] = 0;
	this.add(h, c);
	
	for (j = 0; j < 16; ++j) 
		outv[j + outvoffset] = toByte(h[j]);
	
	return 0;
};