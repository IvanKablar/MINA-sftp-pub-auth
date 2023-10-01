package de.adesso.sftp.configuration;

import de.adesso.sftp.authentication.SftpPublicKeyAuthenticator;
import jakarta.annotation.PreDestroy;
import jakarta.annotation.PostConstruct;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.File;
import java.io.IOException;
import java.util.Collections;

/**
 * Serverkonfiguration. Startet den SSH-Deamon.
 */
@Component
public class SftpServerConfig {

    private SshServer sshd;
    @Value("${hostkey}")
    private String hostKey;
    private final SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator;

    @Autowired
    public SftpServerConfig(SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator) {
        this.sftpPublicKeyAuthenticator = sftpPublicKeyAuthenticator;
    }

    @PostConstruct
    public void init() throws IOException {
        SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder().build();
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(9922);
        sshd.setKeyPairProvider(new SimpleGeneratorHostKeyProvider(new File(hostKey).toPath()));
        sshd.setPublickeyAuthenticator(sftpPublicKeyAuthenticator);
        sshd.setSubsystemFactories(Collections.singletonList(factory));
        sshd.start();
    }

    @PreDestroy
    public void destroy() throws IOException {
        sshd.close();
    }

}
