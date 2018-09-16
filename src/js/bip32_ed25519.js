(function() {
    const jsbn = require('jsbn');
    const jsSHA = require('jssha');
    const blake = require('blakejs');
    const ed25519 = require('./ed25519.js');

    const BigInteger = jsbn.BigInteger;

    BigInteger.prototype.times = BigInteger.prototype.multiply;
    BigInteger.prototype.plus = BigInteger.prototype.add;
    BigInteger.prototype.minus = BigInteger.prototype.subtract;
    BigInteger.prototype.square = function () {
        return this.times(this);
    };
    BigInteger.prototype.lesser = function (a) {
        return (this.compareTo(a) < 0);
    };
    BigInteger.prototype.greater = function (a) {
        return (this.compareTo(a) > 0);
    };
    BigInteger.prototype.equals = function (a) {
        return (this.compareTo(a) == 0);
    };
    BigInteger.prototype.greaterOrEqualTo = function (a) {
        return (this.compareTo(a) >= 0);
    };
    BigInteger.prototype.lesserOrEqualTo = function (a) {
        return (this.compareTo(a) >= 0);
    };
    BigInteger.prototype.lesserThan = BigInteger.prototype.lesser;
    BigInteger.prototype.greaterThan = BigInteger.prototype.greater;
    BigInteger.prototype.equalTo = BigInteger.prototype.equals;


    // BigInteger construction done right
    function bi(s, base) {
        if (base != undefined) {
            if (base == 256) return bytes2bi(string2bytes(s));
            return new BigInteger(s, base);
        } else if (typeof s == 'string') {
            return new BigInteger(s, 10);
        } else if (s instanceof Array) {
            return bytes2bi(s);
        } else if (typeof s == 'number') {
            return new BigInteger(s.toString(), 10);
        } else {
            throw "Can't convert " + s + " to BigInteger";
        }
    }

    var zero = BigInteger.ZERO;
    var one = BigInteger.ONE;
    var two = bi('2');

    function uint8ToHex(uintValue) {
        var hex = "";
        var aux;
        for (var i = 0; i < uintValue.length; i++) {
            aux = uintValue[i].toString(16).toLowerCase();
            if (aux.length == 1)
                aux = '0' + aux;
            hex += aux;
            aux = '';
        }

        return (hex);
    }

    function hexToUint8(hexValue) {
        var length = (hexValue.length / 2) | 0;
        var uint8 = new Uint8Array(length);
        for (let i = 0; i < length; i++) uint8[i] = parseInt(hexValue.substr(i * 2, 2), 16);

        return uint8;
    }

    function h512(m) {
        /*var shaObj = new jsSHA("SHA-512", 'ARRAYBUFFER')
        shaObj.update(m.buffer)
        return new Uint8Array(shaObj.getHash('ARRAYBUFFER'))*/
        return blake.blake2b(m)

    }

    function h256(m) {
        var shaObj = new jsSHA("SHA-256", 'ARRAYBUFFER')
        shaObj.update(m.buffer)
        return new Uint8Array(shaObj.getHash('ARRAYBUFFER'))
    }

    function Fk(message, secret) {
        var self = this;
        var uToH = uint8ToHex;
        var shaObj = new jsSHA("SHA-512", "ARRAYBUFFER")
        shaObj.setHMACKey(secret.buffer, "ARRAYBUFFER")
        shaObj.update(message.buffer)
        return new Uint8Array(shaObj.getHMAC("ARRAYBUFFER"))
    }

    function set_bit(character, pattern) {
        return character | pattern
    }

    function clear_bit(character, pattern) {
        return character & ~pattern
    }

    function root_key(master_secret) {
        if (master_secret.constructor != Uint8Array)
            throw "master_secret must be of type 'Uint8Array'"
        if (master_secret.length != 32)
            throw "master_secret must be 32 bytes (a Uint8Array of size 32)"
        var k = h512(master_secret)
        var kL = k.slice(0, 32), kR = k.slice(32)

        if (kL[31] & 0b00100000) {
            return null
        }

        // clear lowest three bits of the first byte
        kL[0] = clear_bit(kL[0], 0b00000111)
        // clear highest bit of the last byte
        kL[31] = clear_bit(kL[31], 0b10000000)
        // set second highest bit of the last byte
        kL[31] = set_bit(kL[31], 0b01000000)

        // root public key
        var A = ed25519.encodepoint(ed25519.scalarmultbase(ed25519.bytes2bi(kL)))
        // root chain code
        var c = h256(concatenate_uint8_arrays([new Uint8Array([1]), master_secret]))
        return [[kL, kR], A, c]
    }

    function concatenate_uint8_arrays(uint8_arrays) {
        var concatenated_array_length = 0;

        uint8_arrays.forEach(function (arr) {
            concatenated_array_length += arr.length;
        })

        var concatenated_array = new Uint8Array(concatenated_array_length);

        for (var i = 0, starting_length_of_set_op = 0; i < uint8_arrays.length; i++) {
            if (i == 0)
                concatenated_array.set(uint8_arrays[0])
            else {
                starting_length_of_set_op += uint8_arrays[i - 1].length
                concatenated_array.set(uint8_arrays[i], starting_length_of_set_op)
            }
        }

        return concatenated_array
    }

    function private_child_key(node, i) {
        var self = this;
        var uToH = uint8ToHex;
        if (i.constructor != BigInteger) i = bi(i)
        if (!node)
            return null
        // unpack argument
        var kLP = node[0][0], kRP = node[0][1], AP = node[1], cP = node[2]
        if (!(i.greaterOrEqualTo(zero) && i.lesserThan(two.pow(32)))) throw "Index i must be between 0 and 2^32 - 1, inclusive"

        var i_bytes = new Uint8Array(ed25519.bi2bytes(i, 4))
        if (i.lesserThan(two.pow(31))) {
            // regular child
            var Z = Fk(concatenate_uint8_arrays([new Uint8Array([2]), new Uint8Array(AP), i_bytes]), cP)
            var c = Fk(concatenate_uint8_arrays([new Uint8Array([3]), new Uint8Array(AP), i_bytes]), cP).slice(32)
        } else {
            // hardened child
            var Z = Fk(concatenate_uint8_arrays([new Uint8Array([0]), kLP, kRP, i_bytes]), cP)
            var c = Fk(concatenate_uint8_arrays([new Uint8Array([1]), kLP, kRP, i_bytes]), cP).slice(32)
        }

        var ZL = Z.slice(0, 28), ZR = Z.slice(32)

        var kLn = ed25519.bytes2bi(ZL).times(bi(8)).plus(ed25519.bytes2bi(kLP))
        // "If kL is divisible by the base order n, discard the child."
        // - "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
        if (kLn.mod(ed25519.l).equals(zero))
            return null
        var kRn = (
            ed25519.bytes2bi(ZR).plus(ed25519.bytes2bi(kRP))
        ).mod(two.pow(bi(256)))
        var kL = new Uint8Array(ed25519.bi2bytes(kLn, 32))
        var kR = new Uint8Array(ed25519.bi2bytes(kRn, 32))

        var A = ed25519.encodepoint(ed25519.scalarmultbase(ed25519.bytes2bi(kL)))
        return [[kL, kR], A, c]
    }

    function safe_public_child_key(extended_public_key, chain_code, i, return_as_hex = true) {
        if (i.constructor != BigInteger) i = bi(i)
        if (!extended_public_key || !chain_code)
            return null
        var AP = extended_public_key
        var cP = chain_code
        if (!(i.greaterOrEqualTo(zero) && i.lesserThan(two.pow(32)))) throw "Index i must be between 0 and 2^32 - 1, inclusive"

        var i_bytes = new Uint8Array(ed25519.bi2bytes(i, 4))
        if (i.lesserThan(two.pow(31))) {// If regular, non-hardened child
            var Z = Fk(concatenate_uint8_arrays([new Uint8Array([2]), AP, i_bytes]), cP)
            var c = Fk(concatenate_uint8_arrays([new Uint8Array([3]), new Uint8Array(AP), i_bytes]), cP).slice(32)
        }
        else
            throw "Can't create hardened child keys from public key"

        var ZL = Z.slice(0, 28), ZR = Z.slice(32)

        var A = ed25519.encodepoint(
            ed25519.edwards(ed25519.decodepoint(AP), ed25519.scalarmultbase((ed25519.bytes2bi(ZL).times(bi(8)))))
        )

        // VERY IMPORTANT. DO NOT USE A CHILD KEY THAT IS EQUIVALENT TO THE IDENTITY POINT
        // "If Ai is the identity point (0, 1), discard the child."
        // - "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
        if (ed25519.bytes2bi(A).equals(ed25519.encodepoint([one, zero])))
            return null

        if (return_as_hex)
            return [uint8ToHex(new Uint8Array(A)), uint8ToHex(c)]
        else
            return [A, c]
    }

    function special_signing(kL, kR, A, M) { // private/secret key left and right sides kL & kR, public key A, and message M in bytes
        var r = h512(concatenate_uint8_arrays([kR, M]))

        r = ed25519.bytes2bi(r).mod(ed25519.l) // l is  base order n of Section III of "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace"
        var R = ed25519.encodepoint(ed25519.scalarmultbase(r))
        var x = ed25519.bytes2bi(h512(concatenate_uint8_arrays([R, A, M])))
        var S = ed25519.encodeint(r.plus(x.times(ed25519.bytes2bi(kL))).mod(ed25519.l))
        return concatenate_uint8_arrays([R, S])
    }

    // "Let k_tilde be 256-bit master secret. Then derive k = H512(k_tilde)
    // and denote its left 32-byte by kL and right one by kR. If the
    // third highest bit of the last byte of kL is not zero, discard k_tilde"
    // - "BIP32-Ed25519 Hierarchical Deterministic Keys over a Non-linear Keyspace" (https://drive.google.com/file/d/0ByMtMw2hul0EMFJuNnZORDR2NDA/view)
    function generate_proper_master_secret() {

        while (true) {
            var master_secret = new Uint8Array(32)
            window.crypto.getRandomValues(master_secret)
            var k = h512(master_secret)
            var kL = k.slice(0, 32)

            if (!(kL[31] & 0b00100000))
                break
        }

        return master_secret

    }


    function derive_chain(master_secret, chain) {
        var root = root_key(master_secret)
        var node = root

        for (var i = 0, chain = chain.split('/'); i < chain.length; i++) {
            if (!chain[i])
                continue
            if (chain[i].endsWith("'"))
                chain[i] = bi(chain[i].slice(0, -1)).plus(two.pow(31))
            else
                chain[i] = bi(chain[i])
            node = private_child_key(node, chain[i])
        }
        return node
    }

    module.exports = {
        'h512': h512,
        'h256': h256,
        'Fk': Fk,
        'set_bit': set_bit,
        'clear_bit': clear_bit,
        'uint8ToHex': uint8ToHex,
        'hexToUint8': hexToUint8,
        'root_key': root_key,
        'private_child_key': private_child_key,
        'safe_public_child_key': safe_public_child_key,
        'special_signing': special_signing,
        'generate_proper_master_secret': generate_proper_master_secret,
        'derive_chain': derive_chain
    };
})();