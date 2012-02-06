curve25519xsalsa20poly1305 = function() {};

curve25519xsalsa20poly1305.crypto_secretbox_PUBLICKEYBYTES = 32;
curve25519xsalsa20poly1305.crypto_secretbox_SECRETKEYBYTES = 32;
curve25519xsalsa20poly1305.crypto_secretbox_BEFORENMBYTES = 32;
curve25519xsalsa20poly1305.crypto_secretbox_NONCEBYTES = 24;
curve25519xsalsa20poly1305.crypto_secretbox_ZEROBYTES = 32;
curve25519xsalsa20poly1305.crypto_secretbox_BOXZEROBYTES = 16;
	
curve25519xsalsa20poly1305.crypto_box_getpublickey = function(pk, sk)
{
	return curve25519.crypto_scalarmult_base(pk, sk);
};

curve25519xsalsa20poly1305.crypto_box_afternm = function(c, m, mlen, n, k)
{
	return xsalsa20poly1305.crypto_secretbox(c, m, mlen, n, k);
};

curve25519xsalsa20poly1305.crypto_box_beforenm = function(k, pk, sk)
{
	var s = new Array(32);
	var sp = s, sigmap = xsalsa20.sigma;
	
	curve25519.crypto_scalarmult(sp, sk, pk);
	return hsalsa20.crypto_core(k, null, sp, sigmap);
};

curve25519xsalsa20poly1305.crypto_box = function(c, m, mlen, n, pk, sk)
{
	var k = new Array(this.crypto_secretbox_BEFORENMBYTES);
	var kp = k;
	
	this.crypto_box_beforenm(kp, pk, sk);
	return this.crypto_box_afternm(c, m, mlen, n, kp);
};

curve25519xsalsa20poly1305.crypto_box_open = function(m, c, clen, n, pk, sk)
{
	var k = new Array(this.crypto_secretbox_BEFORENMBYTES);
	var kp = k;
	
	this.crypto_box_beforenm(kp, pk, sk);
	return this.crypto_box_open_afternm(m, c, clen, n, kp);
};

curve25519xsalsa20poly1305.crypto_box_open_afternm = function(m, c, clen, n, k)
{
	return xsalsa20poly1305.crypto_secretbox_open(m, c, clen, n, k);
};

curve25519xsalsa20poly1305.crypto_box_afternm = function(c, m, n, k)
{
	var cp = c, mp = m, np = n, kp = k;
	return this.crypto_box_afternm(cp, mp, /*(long)*/m.length, np, kp);
};

curve25519xsalsa20poly1305.crypto_box_open_afternm = function(m, c, n, k)
{
	var cp = c, mp = m, np = n, kp = k;
	return this.crypto_box_open_afternm(mp, cp, /*(long)*/c.length, np, kp);
};

curve25519xsalsa20poly1305.crypto_box = function(c, m, n, pk, sk)
{
	var cp = c, mp = m, np = n, pkp = pk, skp = sk;
	return this.crypto_box(cp, mp, /*(long)*/ m.length, np, pkp, skp);
};

curve25519xsalsa20poly1305.crypto_box_open = function(m, c, n, pk, sk)
{
	var cp = c, mp = m, np = n, pkp = pk, skp = sk;
	return this.crypto_box_open(mp, cp, /*(long)*/c.length, np, pkp, skp);
};