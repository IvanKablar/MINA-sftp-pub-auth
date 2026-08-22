package de.adesso.sftp.configuration;

import de.adesso.sftp.authentication.SftpPublicKeyAuthenticator;
import jakarta.annotation.PreDestroy;
import jakarta.annotation.PostConstruct;
import org.apache.sshd.common.NamedResource;
import org.apache.sshd.common.keyprovider.KeyPairProvider;
import org.apache.sshd.common.util.security.SecurityUtils;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.Collections;

/**
 * Serverkonfiguration. Startet den SSH-Daemon.
 */
@Component
public class SftpServerConfig {

    private SshServer sshd;
    @Value("${hostkey}")
    private String hostKey;
    private final ResourceLoader resourceLoader;
    private final SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator;

    public SftpServerConfig(ResourceLoader resourceLoader, SftpPublicKeyAuthenticator sftpPublicKeyAuthenticator) {
        this.resourceLoader = resourceLoader;
        this.sftpPublicKeyAuthenticator = sftpPublicKeyAuthenticator;
    }

    @PostConstruct
    public void init() throws IOException, GeneralSecurityException {
        SftpSubsystemFactory factory = new SftpSubsystemFactory.Builder().build();
        sshd = SshServer.setUpDefaultServer();
        sshd.setPort(9922);
        sshd.setKeyPairProvider(KeyPairProvider.wrap(loadHostKey()));
        sshd.setPublickeyAuthenticator(sftpPublicKeyAuthenticator);
        sshd.setSubsystemFactories(Collections.singletonList(factory));
        sshd.start();
    }

    /**
     * Liest den Host-Key (PEM oder OpenSSH-Format) aus der konfigurierten Ressource, z. B. classpath:hostkey.pem.
     */
    private Iterable<KeyPair> loadHostKey() throws IOException, GeneralSecurityException {
        Resource resource = resourceLoader.getResource(hostKey);
        try (InputStream in = resource.getInputStream()) {
            return SecurityUtils.loadKeyPairIdentities(null, NamedResource.ofName(hostKey), in, null);
        }
    }

    @PreDestroy
    public void destroy() throws IOException {
        sshd.close();
    }

}
