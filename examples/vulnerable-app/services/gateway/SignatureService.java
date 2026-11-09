package com.nimbus.gateway.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.Base64;
import javax.net.ssl.SSLContext;

/**
 * Signing gateway for outbound payment instructions.
 *
 * The gateway holds a long-lived RSA key pair and signs every ISO 20022
 * message that leaves the estate. Key material is provisioned by the
 * platform team and has not been rotated since the gateway was built.
 */
public final class SignatureService {

    private final KeyPair keyPair;

    public SignatureService() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        this.keyPair = generator.generateKeyPair();
    }

    public String sign(byte[] message) throws Exception {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /** Legacy merchant checksum, retained for the v1 API. */
    public String legacyChecksum(byte[] payload) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return Base64.getEncoder().encodeToString(digest.digest(payload));
    }

    /** TLS context for the acquiring-bank connection. */
    public SSLContext bankContext() throws Exception {
        return SSLContext.getInstance("TLSv1");
    }
}
