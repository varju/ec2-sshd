package org.kohsuke.ec2sshd;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.logging.Logger;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.util.encoders.Base64;

public class EC2InstanceDataKeyProvider extends AbstractKeyProvider {
    private static final Logger LOGGER = Logger.getLogger(EC2InstanceDataKeyProvider.class.getName());
    protected URL keyUrl;

    public EC2InstanceDataKeyProvider() throws MalformedURLException {
        this("http://169.254.169.254/2009-04-04/meta-data/public-keys/0/openssh-key");
    }

    public EC2InstanceDataKeyProvider(String keyUrlString) throws MalformedURLException {
        this(new URL(keyUrlString));
    }

    public EC2InstanceDataKeyProvider(URL keyUrl) {
        this.keyUrl = keyUrl;
    }

    @Override
    public PublicKey getKey() throws IOException, GeneralSecurityException {
        LOGGER.info("Retrieving the key from instance metadata");
        return parseKey(IOUtils.toString(keyUrl.openStream()).trim());
    }
}
