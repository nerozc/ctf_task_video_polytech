
const ENCRYPTION_KEY = CryptoJS.enc.Utf8.parse('ObsidianWallKey!');
const INIT_VECTOR = CryptoJS.enc.Utf8.parse('ShadowGateKeepr!');

document.addEventListener("DOMContentLoaded", function() {
    const token = getCookie("auth_token");
    
    if (token) {
        try {
            const decrypted = decryptToken(token);
            
            console.log(
                "%c[ASH SYSTEM] Connection Established: " + decrypted.user, 
                "background: #111; color: #b8860b; padding: 4px; border: 1px solid #b8860b;"
            );
            
            if (decrypted.role === 'guest') {
                console.warn("%c[ACCESS] Role: OBSERVER. Core access restricted.", "color: #888");
            } else if (decrypted.role === 'admin') {
                console.log("%c[ACCESS] Role: KEEPER. Core Unlocked.", "color: #0f0; font-weight: bold;");
            }
        } catch (e) {
            console.error("Signal Lost. Token corrupted.");
        }
    }
});

function decryptToken(encryptedBase64) {
    const decrypted = CryptoJS.AES.decrypt(encryptedBase64, ENCRYPTION_KEY, {
        iv: INIT_VECTOR,
        mode: CryptoJS.mode.CBC,
        padding: CryptoJS.pad.Pkcs7
    });
    return JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
}

function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(';').shift();
}