package org.kohsuke.ec2sshd;

import java.util.Arrays;
import java.io.File;
import java.io.IOException;
import org.junit.Test;
import static org.junit.Assert.*;

public class KeyProviderTest {
    @Test
    public void testFileKeyProvider() throws Exception {
        String keyFileString = this.getClass().getClassLoader().getResource("basic_file_test.pub").getFile();
        KeyProvider kp = new FileKeyProvider(keyFileString);

        assertNotNull(kp.getKey());
        // Exception may be thrown to fail the test
    }
}
