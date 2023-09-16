package dev.eklak.javaspringauthfeatures.auth.filter;

import dev.eklak.javaspringauthfeatures.auth.UsernamePasswordAuthentication;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Value("${jwt.signing.key}")
    private String signingKey;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
        HttpServletResponse response, FilterChain filterChain) throws
        ServletException, IOException {
        String jwtToken = request.getHeader("Authorization");
        SecretKey key = Keys.hmacShaKeyFor(
            signingKey.getBytes(StandardCharsets.UTF_8)
        );
        // Parses the token to obtain the claims and verifies the signature
        // An exception is thrown if the signature isn't valid
        Claims claims = Jwts.parserBuilder()
            .setSigningKey(key)
            .build()
            .parseClaimsJws(jwtToken)
            .getBody();

        String username = String.valueOf(claims.get("username"));

        // Creates the Authentication instance that we add to the security context
        GrantedAuthority authority = new SimpleGrantedAuthority("user");
        var auth = new UsernamePasswordAuthentication(username, null, List.of(authority));

        // Adds the authentication object to the security context
        SecurityContextHolder.getContext().setAuthentication(auth);

        // Calls the next filter in the filter chain
        filterChain.doFilter(request, response);

    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws
        ServletException {
        // Configures this filter not to be triggered on requests for
        // the /login path
        return request.getServletPath()
            .equals("/login");
    }
}
