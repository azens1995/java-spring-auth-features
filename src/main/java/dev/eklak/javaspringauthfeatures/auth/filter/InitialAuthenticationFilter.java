package dev.eklak.javaspringauthfeatures.auth.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import dev.eklak.javaspringauthfeatures.auth.OtpAuthentication;
import dev.eklak.javaspringauthfeatures.auth.UsernamePasswordAuthentication;
import dev.eklak.javaspringauthfeatures.user.User;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class InitialAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private AuthenticationManager manager;

    // Takes the value of the key used to sign the JWT token from the properties file
    @Value("${jwt.signing.key}")
    private String signingKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
        HttpServletResponse response, FilterChain filterChain) throws
        ServletException, IOException {
//        String requestData = request.getReader().lines().collect(Collectors.joining());
        ObjectMapper mapper = new ObjectMapper();
        User user = mapper.readValue(request.getInputStream(), User.class);
//        String username = request.getHeader("username");
//        String password = request.getHeader("password");
//        String code = request.getHeader("code");

        // Checks if code is present or not, and uses the respective authentication
        if (Objects.isNull(user.getCode())) {
            Authentication a = new UsernamePasswordAuthentication(user.getUsername(), user.getPassword());
            // Calls the authentication manager with username and password authentication
            manager.authenticate(a);
        } else {
            Authentication a = new OtpAuthentication(user.getUsername(), user.getCode());
            manager.authenticate(a);

            SecretKey key = Keys.hmacShaKeyFor(signingKey.getBytes(
                StandardCharsets.UTF_8));
            // Build a JWT and stores the username of the authenticated user
            // as one of it's claims.
            String jwt = Jwts.builder()
                .setClaims(Map.of("username", user.getUsername()))
                .signWith(key)
                .compact();
            // Adds the token to the Authorization header of the response
            response.setHeader("Authorization", jwt);
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !request.getServletPath().equals("/login");
    }
}
