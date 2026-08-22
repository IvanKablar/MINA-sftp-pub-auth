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
     * Validiert den auf dem Server konfigurierten Public-Key und vergleicht ihn mit dem Public-Key des Clients.
     * Stimmen beide Schlüssel überein, ist der Public-Key des Clients gültig.
     *
     * @param serverConfPublicKey der auf dem Server konfigurierte Public-Key (authorized_keys-Format).
     * @param clientPublicKey     der vom Client beim Anmelden geschickte Public-Key.
     * @param serverSession       die Server Session.
     * @return true, wenn der konfigurierte Public-Key valide ist und beide Schlüssel gleich sind, sonst false.
     */
    public boolean isPublicKeyValid(String serverConfPublicKey, PublicKey clientPublicKey, ServerSession serverSession) {
        PublicKey serverPublicKey = getServerPublicKey(serverConfPublicKey, serverSession);
        if (serverPublicKey == null || clientPublicKey == null) {
            return false;
        }
        return compareKeys(clientPublicKey, serverPublicKey);
    }

    /**
     * Holt den auf dem Server konfigurierten Public-Key.
     * @param serverConfPublicKey ist der Public-Key, den der Server hinterlegt hat.
     * @param serverSession ist die ServerSession.
     * @return den Public-Key, wenn er valide ist oder null, wenn nicht.
     */
    private PublicKey getServerPublicKey(String serverConfPublicKey, ServerSession serverSession) {
        try {
            return parsePublicKey(serverConfPublicKey, serverSession);
        } catch (IOException e) {
            log.warn("Fehler beim Dekodieren des serverseitigen Public-Keys", e);
        } catch (IllegalArgumentException e) {
            log.warn("Der serverseitige Public-Key besitzt kein gültiges Format", e);
        } catch (GeneralSecurityException e) {
            log.warn("Fehler beim Generieren des serverseitigen Public-Keys", e);
        }
        return null;
    }

    /**
     * Analysiert den Public-Key im String und prüft, ob dieser ein gültiges Format besitzt, dekodiert werden kann
     * und ein Objekt vom Typ <code>java.security.PublicKey</code> generiert werden kann.
     *
     * @param publicKey     der zu analysierende Public-Key im String-Format.
     * @param serverSession die Server Session
     * @return den generierten Public-Key vom Typ <code>java.security.PublicKey</code>
     * @throws IOException              falls der Public-Key nicht dekodiert werden kann.
     * @throws GeneralSecurityException falls der Rückgabeparameter nicht generiert werden kann.
     */
    private PublicKey parsePublicKey(String publicKey, ServerSession serverSession) throws IOException, GeneralSecurityException {
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
