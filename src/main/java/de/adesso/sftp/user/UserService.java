package de.adesso.sftp.user;

import org.apache.commons.io.IOUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;

/**
 * Hat Zugriff auf die Benutzerkonfiguration für einen Benutzer aus den application.properties und die Public-Key Datei.
 */
@Component
public class UserService {

    private static final Logger log = LogManager.getLogger(UserService.class);
    private ResourceLoader resourceLoader;
    private User user;

    public UserService(ResourceLoader resourceLoader, User user) {
        this.resourceLoader = resourceLoader;
        this.user = user;
    }

    /**
     * Liefert den Public-Key des Benutzers.
     *
     * @param user der Benutzer.
     * @return den Public-Key, falls der Benutzername und der Public-Key konfiguriert wurden, ansonsten null.
     */
    public String getUserKey(User user) {
        Resource resource =  this.resourceLoader.getResource(user.getPubkey());
        try (InputStream in = resource.getInputStream()) {
            return IOUtils.toString(in, Charset.forName("UTF-8"));
        } catch (IOException e) {
            log.warn("Fehler beim Lesen des Public-Key für Benutzer '{}'", user.getName());
            return null;
        }
    }

    public User getUser(String username) {
        if(username.equals(this.user.getName())) {
         return this.user;
        }
        return null;
    }
}
