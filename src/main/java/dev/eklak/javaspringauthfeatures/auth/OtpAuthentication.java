package dev.eklak.javaspringauthfeatures.auth;

import java.util.Collection;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class OtpAuthentication extends UsernamePasswordAuthenticationToken {
    public OtpAuthentication(Object principal, Object credentials) {
        super(principal, credentials);
    }
}
