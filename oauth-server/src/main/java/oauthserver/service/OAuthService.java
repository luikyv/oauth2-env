package oauthserver.service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import oauthserver.configuration.Config;
import oauthserver.enumerations.TokenType;
import oauthserver.domain.model.OAuthFlowSession;
import oauthserver.domain.payload.AccessTokenResponse;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Date;
import java.util.UUID;
import java.util.stream.Collectors;

@Service
@Slf4j
public class OAuthService {

    private final Config config;
    private Key key;

    @Autowired
    public OAuthService(Config config) {
        this.config = config;
        key = Keys.hmacShaKeyFor(config.getSecretKey().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Create a cookie to identify the oauth flow and return its id.
     *
     * @param response
     *          HTTP response which we'll add the cookie.
     * @return The id created for the current flow.
     */
    public String addFlowCookie(HttpServletResponse response) {
        // Create an id to the flow and set a cookie the response
        String flowId = UUID.randomUUID().toString();
        log.info("Flow id: {}", flowId);
        Cookie flowCookie = new Cookie(Config.FLOW_ID_COOKIE, flowId);

        flowCookie.setMaxAge(Config.FLOW_ID_COOKIE_EXPIRE_TIME_SECONDS);
        response.addCookie(flowCookie);

        return flowId;
    }

    /**
     * Build the redirect uri using the values in the current oauth session.
     *
     * @param oAuthFlowSession
     *          It contains the <code>state</code> and <code>authCode</code> created to the oauth flow.
     *          We add these values as query parameters to the base <code>redirectUri</code>.
     * @return The redirect uri.
     */
    public String buildRedirectUri(OAuthFlowSession oAuthFlowSession) {
        return UriComponentsBuilder
                .fromUriString(oAuthFlowSession.getClient().getRedirectUri())
                .queryParam("code", oAuthFlowSession.getAuthCode())
                .queryParam("state", oAuthFlowSession.getState())
                .build().toUriString();
    }

    /**
     * Build the oauth access token response based on the information of the current flow.
     *
     * @param oAuthFlowSession
     *          Information about the oauth flow.
     * @return the access token response.
     */
    public AccessTokenResponse buildAccessTokenResponse(OAuthFlowSession oAuthFlowSession) {
        // Create a String concatenating the names of the scope enums
        String scope = oAuthFlowSession
                .getScopes()
                .stream()
                .map(s -> s.name())
                .collect(Collectors.joining(" ", "", ""));

        // Create and sign the jwt
        String accessToken = Jwts
                .builder()
                .setSubject(oAuthFlowSession.getUser().getUsername())
                .setAudience(oAuthFlowSession.getClient().getId())
                .setExpiration(DateUtils.addSeconds(new Date(), Config.ACCESS_TOKEN_EXPIRE_TIME_DAYS))
                .claim("scope", scope)
                .signWith(this.key)
                .compact();

        return AccessTokenResponse
                .builder()
                .accessToken(accessToken)
                .tokenType(TokenType.bearer)
                .expiresIn(Config.ACCESS_TOKEN_EXPIRE_TIME_DAYS)
                .scope(scope)
                .build();
    }
}
