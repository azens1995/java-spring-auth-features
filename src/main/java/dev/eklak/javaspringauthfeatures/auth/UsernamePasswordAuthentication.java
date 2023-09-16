package dev.eklak.javaspringauthfeatures.auth;

import java.util.Collection;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class UsernamePasswordAuthentication extends UsernamePasswordAuthenticationToken {
    // Note:
    // when you call the one with two parameters, the authentication instance remains
    // unauthenticated, while the one with three parameters sets the Authentication
    // object as authenticated
    public UsernamePasswordAuthentication(Object principal,
        Object credentials) {
        super(principal, credentials);
    }

    public UsernamePasswordAuthentication(Object principal, Object credentials,
        Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }
}
