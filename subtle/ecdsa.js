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
     * @param {string} ivHex
     * @returns
     */
    const decrypt = async (cipherHex, ivHex) => {
        return await crypto.subtle.decrypt(
            { name: 'AES-CBC', iv: hex2buf(ivHex) },
            tmpKeys!.privateKey,
            hex2buf(cipherHex),
        )
    }

    return { tmpKeys, hash, sign, verify, decrypt, buf2hex, hex2buf }
}
