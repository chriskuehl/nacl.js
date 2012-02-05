curve25519 = function() {};

curve25519.CRYPTO_BYTES = 32;
curve25519.CRYPTO_SCALARBYTES = 32;

curve25519.basev = [ 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 ];
curve25519.minusp = [ 19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128 ];

curve25519.crypto_scalarmult_base = function(q, n)
{
	var basevp = basev;
	return crypto_scalarmult(q, n, basevp);
};

curve25519.add = function(outv, outvoffset, a, aoffset, b, boffset)
{
	var u = 0;
	
	for (var j = 0; j < 31; ++j)
	{
		u += a[aoffset + j] + b[boffset + j];
		outv[outvoffset + j] = u & 255;
		u >>>= 8;
	}
	
	u += a[aoffset + 31] + b[boffset + 31];
	outv[outvoffset + 31] = u;
};

curve25519.sub = function(outv, outvoffset, a, aoffset, b, boffset)
{
	var u = 218;
	
	for (var j = 0; j < 31; ++j)
	{
		u += a[aoffset + j] + 65280 - b[boffset + j];
		outv[outvoffset + j] = u & 255;
		u >>>= 8;
	}
	
	u += a[aoffset + 31] - b[boffset + 31];
	outv[outvoffset + 31] = u;
};

curve25519.squeeze = function(a, aoffset)
{
	var u = 0;
	
	for (var j = 0; j < 31; ++j)
	{
		u += a[aoffset + j];
		a[aoffset + j] = u & 255;
		u >>>= 8;
	}
	
	u += a[aoffset + 31];
	a[aoffset + 31] = u & 127;
	u = 19 * (u >>> 7);
	
	for (var j = 0; j < 31; ++j)
	{
		u += a[aoffset + j];
		a[aoffset + j] = u & 255;
		u >>>= 8;
	}
	
	u += a[aoffset + 31];
	a[aoffset + 31] = u;
};

curve25519.freeze = function(a, aoffset)
{
	var aorig = new Array(32);
	
	for (var j = 0; j < 32; ++j)
		aorig[j] = a[aoffset + j];
	
	var minuspp = this.minusp;
	
	this.add(a, 0, a, 0, minuspp, 0);
	
	var negative = parseInt(-((a[aoffset + 31] >>> 7) & 1));
	
	for (var j = 0; j < 32; ++j)
		a[aoffset + j] ^= negative & (aorig[j] ^ a[aoffset + j]);
};

curve25519.mult = function(outv, outvoffset, a, aoffset, b, boffset)
{
	var j;
	
	for (var i = 0; i < 32; ++i)
	{
		var u = 0;
		
		for (j = 0; j <= i; ++j)
			u += a[aoffset + j] * b[boffset + i - j];
		
		for (j = i + 1; j < 32; ++j)
			u += 38 * a[aoffset + j] * b[boffset + i + 32 - j];
		
		outv[outvoffset + i] = u;
	}
	
	this.squeeze(outv, outvoffset);
};

curve25519.mult121665 = function(outv, a)
{
	var j;
	var u = 0;
	
	for (j = 0; j < 31; ++j)
	{
		u += 121665 * a[j];
		outv[j] = u & 255;
		u >>>= 8;
	}
	
	u += 121665 * a[31];
	outv[31] = u & 127;
	u = 19 * (u >>> 7);
	
	for (j = 0; j < 31; ++j)
	{
		u += outv[j];
		outv[j] = u & 255;
		u >>>= 8;
	}
	
	u += outv[j];
	outv[j] = u;
};

curve25519.square = function(outv, outvoffset, a, aoffset)
{
	var j;
	
	for (var i = 0; i < 32; ++i)
	{
		var u = 0;
		
		for (j = 0; j < i - j; ++j)
			u += a[aoffset + j] * a[aoffset + i - j];
		
		for (j = i + 1; j < i + 32 - j; ++j)
			u += 38 * a[aoffset + j] * a[aoffset + i + 32 - j];
		
		u *= 2;
		
		if ((i & 1) == 0)
		{
			u += a[aoffset + i / 2] * a[aoffset + i / 2];
			u += 38 * a[aoffset + i / 2 + 16] * a[aoffset + i / 2 + 16];
		}
		
		outv[outvoffset + i] = u;
	}
	
	this.squeeze(outv, outvoffset);
};

curve25519.select = function(p, q, r, s, b)
{
	var bminus1 = b - 1;
	
	for (var j = 0; j < 64; ++j)
	{
		var t = bminus1 & (r[j] ^ s[j]);
		p[j] = s[j] ^ t;
		q[j] = r[j] ^ t;
	}
};

curve25519.mainloop = function(work, e)
{
	var xzm1 = new Array(64);
	var xzm = new Array(64);
	var xzmb = new Array(64);
	var xzm1b = new Array(64);
	var xznb = new Array(64);
	var xzn1b = new Array(64);
	var a0 = new Array(64);
	var a1 = new Array(64);
	var b0 = new Array(64);
	var b1 = new Array(64);
	var c1 = new Array(64);
	var r = new Array(32);
	var s = new Array(32);
	var t = new Array(32);
	var u = new Array(32);

	for (var j = 0; j < 32; ++j)
		xzm1[j] = work[j];
	
	xzm1[32] = 1;
	
	for (var j = 33; j < 64; ++j)
		xzm1[j] = 0;

	xzm[0] = 1;
	
	for (var j = 1; j < 64; ++j)
		xzm[j] = 0;

	var xzmbp = xzmb, a0p = a0, xzm1bp = xzm1b;
	var a1p = a1, b0p = b0, b1p = b1, c1p = c1;
	var xznbp = xznb, up = u, xzn1bp = xzn1b;
	var workp = work, sp = s, rp = r;

	for (var pos = 254; pos >= 0; --pos)
	{
		var b = (parseInt((e[parseInt(pos / 8)] & 0xFF) >>> (pos & 7)));
		b &= 1;
		this.select(xzmb, xzm1b, xzm, xzm1, b);
		this.add(a0, 	0,	xzmb, 	0,	xzmbp,	32);
		this.sub(a0p,	32,	xzmb, 	0,	xzmbp, 	32);
		this.add(a1, 	0,	xzm1b, 	0,	xzm1bp,	32);
		this.sub(a1p,	32,	xzm1b, 	0,	xzm1bp, 32);
		this.square(b0p,	0,	a0p,	0);
		this.square(b0p, 32,	a0p,	32);
		this.mult(b1p,	0,	a1p,	0, 	a0p,	32);
		this.mult(b1p,	32,	a1p,	32,	a0p,	0);
		this.add(c1, 	0,	b1, 	0,	b1p,	32);
		this.sub(c1p,	32,	b1,		0,	b1p,	32);
		this.square(rp,	0,	c1p,	32);
		this.sub(sp,		0,	b0,		0,	b0p,	32);
		this.mult121665(t, s);
		this.add(u, 		0,	t, 		0,	b0p,	0);
		this.mult(xznbp,	0,	b0p,	0,	b0p,	32);
		this.mult(xznbp,	32, sp,		0,	up,		0);
		this.square(xzn1bp, 0, c1p,	0);
		this.mult(xzn1bp, 32, rp, 	0, 	workp, 	0);
		this.select(xzm, xzm1, xznb, xzn1b, b);
	}

	for (var j = 0; j < 64; ++j)
		work[j] = xzm[j];
};

curve25519.recip = function(outv, outvoffset, z, zoffset)
{
	var z2 = new Array(32);
	var z9 = new Array(32);
	var z11 = new Array(32);
	var z2_5_0 = new Array(32);
	var z2_10_0 = new Array(32);
	var z2_20_0 = new Array(32);
	var z2_50_0 = new Array(32);
	var z2_100_0 = new Array(32);
	var t0 = new Array(32);
	var t1 = new Array(32);

	/* 2 */
	var z2p = z2;
	this.square(z2p, 0, z, zoffset);
	
	/* 4 */
	this.square(t1, 0, z2, 0);
	
	/* 8 */
	this.square(t0, 0, t1, 0);
	
	/* 9 */
	var z9p = z9, t0p = t0;
	this.mult(z9p, 0, t0p, 0, z, zoffset);
	
	/* 11 */
	this.mult(z11, 0, z9, 0, z2, 0);
	
	/* 22 */
	this.square(t0, 0, z11, 0);
	
	/* 2^5 - 2^0 = 31 */
	this.mult(z2_5_0, 0, t0, 0, z9, 0);

	/* 2^6 - 2^1 */
	this.square(t0, 0, z2_5_0, 0);
	
	/* 2^7 - 2^2 */
	this.square(t1, 0, t0, 0);
	
	/* 2^8 - 2^3 */
	this.square(t0, 0, t1, 0);
	
	/* 2^9 - 2^4 */
	this.square(t1, 0, t0, 0);
	
	/* 2^10 - 2^5 */
	this.square(t0, 0, t1, 0);
	
	/* 2^10 - 2^0 */
	this.mult(z2_10_0, 0, t0, 0, z2_5_0, 0);

	/* 2^11 - 2^1 */
	this.square(t0, 0, z2_10_0, 0);
	
	/* 2^12 - 2^2 */
	this.square(t1, 0, t0, 0);
	
	/* 2^20 - 2^10 */
	for (var i = 2; i < 10; i += 2)
	{ 
		this.square(t0, 0, t1, 0);
		this.square(t1, 0, t0, 0);
	}
	
	/* 2^20 - 2^0 */
	this.mult(z2_20_0, 0, t1, 0, z2_10_0, 0);

	/* 2^21 - 2^1 */
	this.square(t0, 0, z2_20_0, 0);
	
	/* 2^22 - 2^2 */
	this.square(t1, 0, t0, 0);
	
	/* 2^40 - 2^20 */
	for (var i = 2; i < 20; i += 2) 
	{ 
		this.square(t0, 0, t1, 0); 
		this.square(t1, 0, t0, 0); 
	}
	
	/* 2^40 - 2^0 */
	this.mult(t0, 0, t1, 0, z2_20_0, 0);

	/* 2^41 - 2^1 */
	this.square(t1, 0, t0, 0);
	
	/* 2^42 - 2^2 */
	this.square(t0, 0, t1, 0);
	
	/* 2^50 - 2^10 */
	for (var i = 2; i < 10; i += 2) 
	{ 
		this.square(t1, 0, t0, 0); 
		this.square(t0, 0, t1, 0); 
	}
	
	/* 2^50 - 2^0 */
	this.mult(z2_50_0, 0, t0, 0, z2_10_0, 0);

	/* 2^51 - 2^1 */
	this.square(t0, 0, z2_50_0, 0);
	
	/* 2^52 - 2^2 */
	this.square(t1, 0, t0, 0);
	
	/* 2^100 - 2^50 */
	for (var i = 2; i < 50; i += 2)
	{ 
		this.square(t0, 0, t1, 0); 
		this.square(t1, 0, t0, 0); 
	}
	
	/* 2^100 - 2^0 */
	this.mult(z2_100_0, 0, t1, 0, z2_50_0, 0);

	/* 2^101 - 2^1 */
	this.square(t1, 0, z2_100_0, 0);
	
	/* 2^102 - 2^2 */
	this.square(t0, 0, t1, 0);
	
	/* 2^200 - 2^100 */
	for (var i = 2; i < 100; i += 2)
	{
		this.square(t1, 0, t0, 0);
		this.square(t0, 0, t1, 0);
	}
	
	/* 2^200 - 2^0 */
	this.mult(t1, 0, t0, 0, z2_100_0, 0);

	/* 2^201 - 2^1 */
	this.square(t0, 0, t1, 0);
	
	/* 2^202 - 2^2 */
	this.square(t1, 0, t0, 0);
	
	/* 2^250 - 2^50 */
	for (var i = 2; i < 50; i += 2)
	{
		this.square(t0, 0, t1, 0);
		this.square(t1, 0, t0, 0);
	}
	
	/* 2^250 - 2^0 */
	this.mult(t0, 0, t1, 0, z2_50_0, 0);

	/* 2^251 - 2^1 */
	this.square(t1, 0, t0, 0);
	
	/* 2^252 - 2^2 */
	this.square(t0, 0, t1, 0);
	
	/* 2^253 - 2^3 */
	this.square(t1, 0, t0, 0);
	
	/* 2^254 - 2^4 */
	this.square(t0, 0, t1, 0);
	
	/* 2^255 - 2^5 */
	this.square(t1, 0, t0, 0);
	
	/* 2^255 - 21 */
	var t1p = t1, z11p = z11;
	
	this.mult(outv, outvoffset, t1p, 0, z11p, 0);
};

curve25519.crypto_scalarmult = function(q, n, p)
{
	var work = new Array(96);
	var e = new Array(32);
	
	for (var i = 0; i < 32; ++i)
		e[i] = n[i];
	
	e[0] &= 248;
	e[31] &= 127;
	e[31] |= 64;
	
	for (var i = 0; i < 32; ++i)
		work[i] = p[i] & 0xFF;
	
	this.mainloop(work, e);
	
	this.recip(work, 32, work, 32);
	this.mult(work, 64, work, 0, work, 32);		
	this.freeze(work, 64);
	
	for (var i = 0; i < 32; ++i)
		q[i] = toByte(work[64 + i]);
	
	return 0;
};