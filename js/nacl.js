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