package oauthserver.service;

import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import oauthserver.configuration.Config;
import oauthserver.domain.dto.AccessTokenResponse;
import oauthserver.domain.model.OAuthFlowSession;
import oauthserver.enumerations.Scope;
import oauthserver.enumerations.TokenType;
import org.apache.commons.lang3.time.DateUtils;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * It performs all the activities we need concerning tokens.
 */
@Service
@AllArgsConstructor
public class TokenService {

    private final Key key;

    /**
     * Build a String from a list of scopes.
     *
     * @param scopes
     *          List of scopes requested by the client.
     * @return A String concatenating the scopes and separating them by spaces.
     */
    private String stringfyScopes(List<Scope> scopes) {
        return scopes
                .stream()
                .map(s -> s.name())
                .collect(Collectors.joining(" ", "", ""));
    }

    /**
     * Create a map containing the user information request by the client.
     *
     * @param oAuthFlowSession
     *          It contains information about the oauth flow.
     * @return
     *          A map containing information about the user based on the openid scopes
     *          requested by the client.
     */
    private Map<String, Object> getOpenIdUserSpecificClaims(OAuthFlowSession oAuthFlowSession) {
        List<Scope> scopes = oAuthFlowSession.getScopes();
        Map<String, Object> openIdClaims = new HashMap();

        if(scopes.contains(Scope.email)) {
            openIdClaims.put("email", oAuthFlowSession.getUser().getUsername());
        }
        if(scopes.contains(Scope.name)) {
            openIdClaims.put("email", oAuthFlowSession.getUser().getName());
        }

        return openIdClaims;
    }

    /**
     * Create an id token with the information requested by the client.
     * The information requested is defined by the scopes consented by the user.
     *
     * @param oAuthFlowSession
     *          It contains information about the oauth flow.
     * @return A signed token with the user's information requested by the client.
     */
    private String buildIdToken(OAuthFlowSession oAuthFlowSession) {

        return Jwts.builder()
                .setIssuer(Config.ISSUER_NAME)
                .setSubject(oAuthFlowSession.getUser().getUsername())
                .setAudience(oAuthFlowSession.getClient().getId())
                .setIssuedAt(new Date())
                .setExpiration(DateUtils.addSeconds(new Date(), Config.ID_TOKEN_EXPIRE_TIME_SECONDS))
                .addClaims(this.getOpenIdUserSpecificClaims(oAuthFlowSession))
                .signWith(this.key) .compact();
    }

    /**
     * Build the oauth access token response based on the information of the current flow.
     *
     * @param oAuthFlowSession
     *          Information about the oauth flow.
     * @return the access token response.
     */
    public AccessTokenResponse buildAccessTokenResponse(OAuthFlowSession oAuthFlowSession) {

        List<Scope> scopes = oAuthFlowSession.getScopes();
        String strScopes = this.stringfyScopes(oAuthFlowSession.getScopes());

        // Create tokens
        String accessToken = Jwts
                .builder()
                .setSubject(oAuthFlowSession.getUser().getUsername())
                .setIssuer(Config.ISSUER_NAME)
                .setIssuedAt(new Date())
                .setExpiration(DateUtils.addSeconds(new Date(), Config.ACCESS_TOKEN_EXPIRE_TIME_SECONDS))
                .claim("scope", strScopes)
                .signWith(this.key)
                .compact();
        // We only provide an id token if the client requested it by passing the scope 'openid'
        String idToken = scopes.contains(Scope.openid) ? this.buildIdToken(oAuthFlowSession) : null;

        return AccessTokenResponse
                .builder()
                .accessToken(accessToken)
                .idToken(idToken)
                .tokenType(TokenType.bearer)
                .expiresIn(Config.ACCESS_TOKEN_EXPIRE_TIME_SECONDS)
                .scope(strScopes)
                .build();
    }
}
