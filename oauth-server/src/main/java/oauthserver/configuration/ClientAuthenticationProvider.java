package oauthserver.configuration;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauthserver.enumerations.Role;
import oauthserver.service.ClientService;
import oauthserver.service.exceptions.ClientNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@AllArgsConstructor
@Slf4j
public class ClientAuthenticationProvider implements AuthenticationProvider {

    private final ClientService clientService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String clientId = authentication.getName();
        String clientSecret = authentication.getCredentials().toString();

        // Verify if the client exists and if his credentials are valid
        boolean areCredentialsValid = false;
        try {
            areCredentialsValid = this.clientService.validateCredentials(clientId, clientSecret);
        } catch (ClientNotFoundException e) {
            log.info("Invalid credentials");
            throw new BadCredentialsException("Client not found");
        }
        if(!areCredentialsValid) {
            log.info("Invalid credentials");
            throw new BadCredentialsException("Invalid secret");
        }

        return new UsernamePasswordAuthenticationToken(
                clientId,
                clientSecret,
                List.of(new SimpleGrantedAuthority(Role.CLIENT.getRoleName()))
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }
}
