async function useECDSA(algorithm = {name:'ECDSA',hash:'SHA-256'}) {
    /** @type {CryptoKeyPair} */
    let tmpKeys

    await crypto.subtle
        .generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify'])
        .then(keys => keys)
        .then(keys => { tmpKeys = keys })
        .catch(console.error)

    /**
     * @param {ArrayBuffer} buffer 
     * @returns 
     */
    const buf2hex = (buffer) => [...new Uint8Array(buffer)].map(
        c => c.toString(16).padStart(2,'0')
    ).join('')

    /**
     * @param {string} hex 
     * @returns
     */
    const hex2buf = (hex) => {
        return new Uint8Array(hex.match(/../g).map(h=>parseInt(h,16))).buffer
    }

    /**
     * @param {string} data 
     * @returns 
     */
    const hash = (data) => {
        return new Uint8Array(data.split('')
            .map(c => c.charCodeAt(0)))
    }

    /**
     * @param {Uint8Array} hash 
     * @returns 
     */
    const sign = async (hash) => {
        return await crypto.subtle.sign(
            algorithm,
            tmpKeys.privateKey,
            hash
        )
    }

    /**
     * @param {Uint8Array} hash 
     * @param {Uint8Array} sig 
     * @returns 
     */
    const verify = async (hash, sig, pub = tmpKeys.publicKey) => {
        return await crypto.subtle.verify(
            algorithm,
            pub,
            sig,
            hash
        )
    }

    /**
     * @param {string} cipherHex
     * @param {string} ephemeralPublicKeyHex
     * @param {string} ivHex
     * @returns
     */
    const decrypt = async (cipherHex, ephemeralPublicKeyHex, ivHex) => {

        const privateKeyJwk = await crypto.subtle.exportKey('jwk', tmpKeys!.privateKey)
        privateKeyJwk.key_ops = [ 'deriveBits' ];
        const privateKey = await crypto.subtle.importKey('jwk',
            privateKeyJwk, {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
        false, [ 'deriveBits' ])

        const xHex = ephemeralPublicKeyHex.slice(2, 66);    // Extract X
        const yHex = ephemeralPublicKeyHex.slice(66);       // Extract Y
        const ephemeralPublicKeyJwk = {
            kty: 'EC',
            crv: 'P-256',
            x: base64UrlEncode(hex2uint8array(xHex)),
            y: base64UrlEncode(hex2uint8array(yHex)),
        };

        const ephemeralPublicKey = await crypto.subtle.importKey('jwk',
            ephemeralPublicKeyJwk, {
                name: 'ECDH',
                namedCurve: 'P-256'
            },
        false, []);

        const sharedSecret = await crypto.subtle.deriveBits({
            name: 'ECDH',
            public: ephemeralPublicKey
        }, privateKey, 256)

        const aesHash = await crypto.subtle.digest('SHA-256', sharedSecret)
        const aesKey = await crypto.subtle.importKey('raw',
            aesHash, {
                name: 'AES-CTR'
            },
        false, [ 'decrypt' ])
        
        const iv     = hex2buf(ivHex)
        const cipher = hex2buf(cipherHex)
        const plaintextBuffer = await crypto.subtle.decrypt({
            name: 'AES-CTR',
            counter: iv,
            length: 128
        }, aesKey, cipher);

        return new TextDecoder().decode(plaintextBuffer);
    }

    return { tmpKeys, hash, sign, verify, decrypt, buf2hex, hex2buf }
}
