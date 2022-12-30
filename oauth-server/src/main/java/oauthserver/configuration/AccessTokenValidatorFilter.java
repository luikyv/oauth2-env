package oauthserver.configuration;

import io.jsonwebtoken.JwtException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauthserver.enumerations.Scope;
import oauthserver.service.TokenService;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@AllArgsConstructor
@Slf4j
public class AccessTokenValidatorFilter extends OncePerRequestFilter {

    private final TokenService tokenService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = request.getHeader(Constant.AUTHORIZATION_HEADER);
        String accessToken = authorizationHeader != null && authorizationHeader.startsWith(Constant.BEARER_PREFIX) ?
                authorizationHeader.substring(Constant.BEARER_PREFIX.length()) : null;

        if(accessToken != null) {

            try {
                // Throw JwtException if the token is invalid
                List<Scope> scopes = tokenService.getScopes(accessToken);
                List<SimpleGrantedAuthority> authorities = scopes.stream().map(
                        scope -> new SimpleGrantedAuthority(scope.name())).collect(Collectors.toList()
                );

                Authentication auth = new UsernamePasswordAuthenticationToken(null, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);

            } catch (JwtException e) {
                log.warn("Invalid access token tried to authenticate. Token: {}", accessToken);
            }
        }

        filterChain.doFilter(request, response);
    }
}
