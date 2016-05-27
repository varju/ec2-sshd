package org.kohsuke.ec2sshd;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

interface KeyProvider {
    public PublicKey getKey() throws IOException, GeneralSecurityException;;
}
