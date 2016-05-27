package org.kohsuke.ec2sshd;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import org.apache.commons.io.IOUtils;

public class FileKeyProvider extends AbstractKeyProvider {
    protected File keyFile;

    public FileKeyProvider(String keyFileString) {
        this(new File(keyFileString));
    }

    public FileKeyProvider(File keyFile) {
        this.keyFile = keyFile;
    }

    @Override
    public PublicKey getKey() throws IOException, GeneralSecurityException {
        return parseKey(IOUtils.toString(new FileInputStream(keyFile)));
    }
}
