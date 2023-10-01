package de.adesso.sftp.authentication;

import org.apache.logging.log4j.Logger;
import org.apache.sshd.common.config.keys.KeyUtils;
import org.apache.sshd.common.config.keys.PublicKeyEntry;
import org.apache.sshd.common.config.keys.PublicKeyEntryResolver;
import org.apache.sshd.server.session.ServerSession;
import org.apache.logging.log4j.LogManager;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

/**
 * Analysiert und vergleicht die Public-Keys des Servers und des Clients.
 */
@Component
public class PublicKeyService {

    private static final Logger log = LogManager.getLogger(PublicKeyService.class);

    /**
     * Validiert und vergleicht die Public-Keys des Servers und des Clients. Stimmen beide Schlüssel übereinstimmen, ist
     * der Public-Key des Clients gültig.
     *
     * @param serverConfPublicKey der auf dem Server konfigurierte Public-Key.
     * @param clientSentPublicKey der vom Client beim Anmelden geschickte Public-Key.
     * @param serverSession       die Server Session.
     * @return true, wenn die Public-Key valide und gleich sind, sonst false.
     */
    public boolean isPublicKeyValid(String serverConfPublicKey, String clientSentPublicKey, ServerSession serverSession) {
        PublicKey serverPublicKey = getServerPublicKey(serverConfPublicKey, serverSession);
        if (serverPublicKey == null) return false;

        PublicKey clientPublicKey = getClientPublicKey(clientSentPublicKey, serverSession);
        if (clientPublicKey == null) return false;
        return compareKeys(clientPublicKey, serverPublicKey);
    }

    /**
     * Holt den Public-Key des Clients.
     * @param clientSentPublicKey ist der Public-Key, den der Benutzer/Client schickt.
     * @param serverSession ist die ServerSession.
     * @return den Public-Key, wenn er valide ist oder null, wenn nicht.
     */
    private PublicKey getClientPublicKey(String clientSentPublicKey, ServerSession serverSession) {
        PublicKey clientPublicKey;
        try {
            clientPublicKey = generatePublicKey(clientSentPublicKey, serverSession);
        } catch (IOException e) {
            log.warn("Fehler beim Dekodieren des clientseitigen Public-Keys", e);
            return null;
        } catch (IllegalArgumentException e) {
            log.warn("Der clientseitige Public-Key besitzt kein gültiges Format", e);
            return null;
        } catch (GeneralSecurityException e) {
            log.warn("Fehler beim Generieren des clientseitigen Public-Keys", e);
            return null;
        }
        return clientPublicKey;
    }

    /**
     * Holt den Public-Key des Clients.
     * @param serverConfPublicKey ist der Public-Key, den der Server hinterlegt hat.
     * @param serverSession ist die ServerSession.
     * @return den Public-Key, wenn er valide ist oder null, wenn nicht.
     */
    private PublicKey getServerPublicKey(String serverConfPublicKey, ServerSession serverSession) {
        PublicKey serverPublicKey;
        try {
            serverPublicKey = generatePublicKey(serverConfPublicKey, serverSession);
        } catch (IOException e) {
            log.warn("Fehler beim Dekodieren des serverseitigen Public-Keys", e);
            return null;
        } catch (IllegalArgumentException e) {
            log.warn("Der serverseitige Public-Key besitzt kein gültiges Format", e);
            return null;
        } catch (GeneralSecurityException e) {
            log.warn("Fehler beim Generieren des serverseitigen Public-Keys", e);
            return null;
        }
        return serverPublicKey;
    }

    /**
     * Analysiert den Public-Key im String und prüft, ob dieser ein gültiges Format besitzt, dekodiert werden kann
     * und ein Objekt vom Typ <java.security.PublicKey> generiert werden kann.
     *
     * @param publicKey     der zu analysierende Public-Key im String-Format.
     * @param serverSession die Server Session
     * @return den generiert Public-Key vom typ <code>java.security.PublicKey</code>
     * @throws IOException              falls der Public-Key nicht dekodiert werden kann.
     * @throws GeneralSecurityException falls der Rückgabeparameter nicht generiert werden kann.
     */
    private PublicKey generatePublicKey(String publicKey, ServerSession serverSession) throws IOException, GeneralSecurityException {
        if (publicKey == null || publicKey.isEmpty()) {
            return null;
        }
        PublicKeyEntry publicKeyEntry = PublicKeyEntry.parsePublicKeyEntry(publicKey);
        return publicKeyEntry.resolvePublicKey(serverSession, null, PublicKeyEntryResolver.IGNORING);
    }

    /**
     * Prüft, ob zwei Public-Keys gleich sind.
     *
     * @param clientPublicKey       der vom Client geschickte Public-Key.
     * @param serverConfigPublicKey der auf dem Server konfigurierte Public-Key
     * @return true, falls die Public-Keys gleich sind, sonst false.
     */
    private boolean compareKeys(PublicKey clientPublicKey, PublicKey serverConfigPublicKey) {
        if (!KeyUtils.compareKeys(clientPublicKey, serverConfigPublicKey)) {
            log.warn("Die Public-Keys stimmen nicht überein");
            return false;
        }
        log.info("Die Public-Keys stimmen überein");
        return true;
    }

}
