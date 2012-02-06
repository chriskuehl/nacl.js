// clone of Java's String.getBytes
// source: http://stackoverflow.com/questions/1240408/reading-bytes-from-a-javascript-string
function stringToBytes(str) { 
	var ch, st, re = [], j = 0;

	for (var i = 0; i < str.length; i ++) { 
		ch = str.charCodeAt(i);

		if (ch < 127) {
			re[j ++] = ch & 0xFF;
		} else {
			st = [];    // clear stack

			do {
				st.push(ch & 0xFF);  // push byte to stack
				ch = ch >> 8;          // shift value down by 1 byte
			}
			while (ch);

			// add stack contents to result
			// done because chars have "wrong" endianness
			st = st.reverse();
			for (var k = 0; k < st.length; ++ k) {
				re[j ++] = st[k];
			}
		}
	}   
	// return an array of bytes
	return re; 
}

// clone of Java's String(byte[]) constructor
// source: http://stackoverflow.com/questions/3195865/javascript-html-converting-byte-array-to-string
function bytesToString(bytes) {
	return String.fromCharCode.apply(String, bytes);
}

// near clone of Java's casting of integers to bytes
// warning: doesn't handle negative integers properly
function toByte(i) {
	return ((i + 128) % 256) - 128;
}