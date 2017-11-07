package org.kohsuke.ec2sshd;

import com.github.fommil.ssh.SshRsaCrypto;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import org.bouncycastle.util.encoders.Base64;

abstract public class AbstractKeyProvider implements KeyProvider {
    abstract public PublicKey getKey() throws IOException, GeneralSecurityException;
    protected PublicKey parseKey(String keyData) throws IOException, GeneralSecurityException {
        String[] keyComponents = keyData.trim().split(" ");
        if (keyComponents.length < 2) {
            throw new IOException("Unexpected instance metadata: " + keyData);
        }
        SshRsaCrypto rsa = new SshRsaCrypto();
        return rsa.readPublicKey(rsa.slurpPublicKey(keyData));
    }
}
