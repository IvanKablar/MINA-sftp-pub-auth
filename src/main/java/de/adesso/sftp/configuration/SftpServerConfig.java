package de.adesso.sftp.configuration;

import de.adesso.sftp.authentication.SftpPublicKeyAuthenticator;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.subsystem.sftp.SftpSubsystemFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
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
    private ResourceLoader resourceLoader;
    private SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator;

    @Autowired
    public SftpServerConfig(ResourceLoader resourceLoader, SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator) {
        this.resourceLoader = resourceLoader;
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
