package de.adesso.sftp.authentication;

import de.adesso.sftp.user.User;
import de.adesso.sftp.user.UserService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.server.auth.AsyncAuthException;
import org.apache.sshd.server.auth.pubkey.PublickeyAuthenticator;
import org.apache.sshd.server.session.ServerSession;
import org.springframework.stereotype.Component;

import java.security.PublicKey;

/**
 * Implementiert die Schnittstelle 'PublickeyAuthenticator'.
 */
@Component
public class SftpPublicKeyAuthenticator implements PublickeyAuthenticator {

    private static final Logger log = LogManager.getLogger(SftpPublicKeyAuthenticator.class);
    private final PublicKeyService publicKeyService;
    private final UserService userService;

    public SftpPublicKeyAuthenticator(PublicKeyService publicKeyService, UserService userService) {
        this.publicKeyService = publicKeyService;
        this.userService = userService;
    }

    /**
     * Prüft, ob der vom Client geschickte Benutzername und Public-Key auf dem Server konfiguriert wurden und der
     * vom client geschickte Public-Key gültig ist.
     *
     * @param username der vom Client geschickte Benutzername.
     * @param publicKey der vom Client geschickte Public-Key
     * @param serverSession die Server Session
     * @return true, falls die Authentifizierung erfolgreich war, sonst false
     * @throws AsyncAuthException falls zur Laufzeit ein Fehler auftritt.
     */
    @Override
    public boolean authenticate(String username, PublicKey publicKey, ServerSession serverSession) throws AsyncAuthException {
        User user =  userService.getUser(username);
        if(user== null) {
            log.warn("Kein Benutzer mit Namen '{}' konfiguriert", username);
            return false;
        }
        return publicKeyService.isPublicKeyValid(userService.getUserKey(user), PublicKeyEntry.toString(publicKey), serverSession);
    }

}
