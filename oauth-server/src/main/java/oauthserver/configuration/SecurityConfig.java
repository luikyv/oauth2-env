package oauthserver.configuration;

import io.jsonwebtoken.security.Keys;
import oauthserver.enumerations.Role;
import oauthserver.enumerations.Scope;
import oauthserver.service.TokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.nio.charset.StandardCharsets;
import java.security.Key;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${secret_key}")
    private String secretKey;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        TokenService tokenService = new TokenService(this.jwtSecretSigningKey(), new StringToScopeListConverter());

        http.csrf().disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                .and().addFilterAfter(new AccessTokenValidatorFilter(tokenService), BasicAuthenticationFilter.class)
                .authorizeHttpRequests()
                    .antMatchers("/token", "/token_info").hasRole(Role.CLIENT.name())
                    .antMatchers("/user_info").hasAuthority(Scope.openid.name())
                    .anyRequest().permitAll()
                .and().httpBasic()
                .and().formLogin().disable();
        return http.build();

    }
    @Bean
    public PasswordEncoder encoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public Key jwtSecretSigningKey() {
        return Keys.hmacShaKeyFor(this.secretKey.getBytes(StandardCharsets.UTF_8));
    }

}
