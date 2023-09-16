package dev.eklak.javaspringauthfeatures.config;

import dev.eklak.javaspringauthfeatures.auth.providers.OtpAuthenticationProvider;
import dev.eklak.javaspringauthfeatures.auth.providers.UsernamePasswordAuthenticationProvider;
import dev.eklak.javaspringauthfeatures.auth.filter.InitialAuthenticationFilter;
import dev.eklak.javaspringauthfeatures.auth.filter.JwtAuthenticationFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    @Bean // Adds the AuthenticationManager to the Spring context so that we can autowire it from the filter class
    protected AuthenticationManager authenticationManager() throws Exception {
        return super.authenticationManager();
    }

    @Autowired
    private InitialAuthenticationFilter initialAuthenticationFilter;

    @Autowired
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @Autowired
    private OtpAuthenticationProvider otpAuthenticationProvider;

    @Autowired
    private UsernamePasswordAuthenticationProvider usernamePasswordAuthenticationProvider;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws
        Exception {
        // Configures both authentication providers to the authentication manager
        auth.authenticationProvider(otpAuthenticationProvider)
            .authenticationProvider(usernamePasswordAuthenticationProvider);
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable(); // Disable csrf
        // Adds both filters to the filter chain
        http.addFilterAt(
                initialAuthenticationFilter,
                BasicAuthenticationFilter.class)
            .addFilterAfter(
                jwtAuthenticationFilter,
                BasicAuthenticationFilter.class
            );

        // Ensures that all requests are authenticated
        http.authorizeRequests()
            .anyRequest()
            .authenticated();

    }
}
