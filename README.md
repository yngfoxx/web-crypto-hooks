# web-crypto-hooks
Web Crypto Hooks

## Usage

Import hook into your project

### ECDSA hook example
```
<script>
importScripts(
    `https://cdn.jsdelivr.net/gh/yngfoxx/web-crypto-hooks/subtle/ecdsa.js`
)

const cert     = await useECDSA()
const hash     = cert.hash('test-message-to-hash')
const sig      = await cert.sign(hash)

// verify signature sample
const isValid  = await cert.verify(hash, sig)
if (!isValid) {
    alert('cert or signature is invalid')
    return;
}

const certificate = JSON.stringify({
    'hsh': cert.buf2hex(hash.buffer),
    'sig': cert.buf2hex(new Uint8Array(sig).buffer),
    'pbk': cert.buf2hex(new Uint8Array(pbk).buffer)
})
</script>
```
