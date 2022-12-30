package oauthserver.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import lombok.AllArgsConstructor;
import oauthserver.configuration.Constant;
import oauthserver.configuration.StringToScopeListConverter;
import oauthserver.domain.dto.AccessTokenIntrospectionResponse;
import oauthserver.domain.dto.AccessTokenResponse;
import oauthserver.domain.dto.UserInfoResponse;
import oauthserver.domain.model.OAuthFlowSession;
import oauthserver.domain.model.User;
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
    private final StringToScopeListConverter stringToScopeListConverter;

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
     * @param scopes
     *          Scopes consented by the user.
     * @param user
     *          User that granted the scopes.
     * @return
     *          A map containing information about the user based on the openid scopes
     *          requested by the client.
     */
    public Map<String, Object> getOpenIdUserSpecificClaims(List<Scope> scopes, User user) {
        Map<String, Object> openIdClaims = new HashMap();

        if(scopes.contains(Scope.email)) {
            openIdClaims.put("email", user.getUsername());
        }
        if(scopes.contains(Scope.name)) {
            openIdClaims.put("name", user.getName());
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
                .setIssuer(Constant.ISSUER_NAME)
                .setSubject(oAuthFlowSession.getUser().getUsername())
                .setAudience(oAuthFlowSession.getClient().getId())
                .setIssuedAt(new Date())
                .setExpiration(DateUtils.addSeconds(new Date(), Constant.ID_TOKEN_EXPIRE_TIME_SECONDS))
                .addClaims(this.getOpenIdUserSpecificClaims(oAuthFlowSession.getScopes(), oAuthFlowSession.getUser()))
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
        String strScopes = stringfyScopes(scopes);

        // Create tokens
        String accessToken = Jwts
                .builder()
                .claim("client_id", oAuthFlowSession.getClient().getId())
                .setSubject(oAuthFlowSession.getUser().getUsername())
                .setIssuer(Constant.ISSUER_NAME)
                .setIssuedAt(new Date())
                .setExpiration(DateUtils.addSeconds(new Date(), Constant.ACCESS_TOKEN_EXPIRE_TIME_SECONDS))
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
                .expiresIn(Constant.ACCESS_TOKEN_EXPIRE_TIME_SECONDS)
                .scope(strScopes)
                .build();
    }

    /**
     * Unpack the information contained in the access token.
     *
     * @param token
     *          Access token created by the Authorization Server.
     * @return The information contained in the access token.
     */
    public AccessTokenIntrospectionResponse getAccessTokenInformation(String token) {

        Claims claims;
        try {
            claims = getClaims(token);
        } catch (JwtException e) {
            return AccessTokenIntrospectionResponse
                    .builder()
                    .active(false)
                    .build();
        }

        return AccessTokenIntrospectionResponse
                .builder()
                .active(true)
                .scope(claims.get("scope", String.class))
                .clientId(claims.get("client_id", String.class))
                .username(claims.getSubject())
                .exp(claims.getExpiration().getTime())
                .build();
    }

    /**
     * Parse the claims in the <code>accessToken</code>.
     *
     * @param accessToken
     *          JWT.
     * @return The claims contained in the <code>accessToken</code>.
     */
    public Claims getClaims(String accessToken) {
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
    }

    /**
     * Parse the scopes contained in the <code>accessToken</code> and convet them to a list.
     *
     * @param accessToken
     *          JWT.
     * @return List of scopes contained in the <code>accessToken</code>.
     */
    public List<Scope> getScopes(String accessToken) {
        Claims claims = getClaims(accessToken);
        String strScopes = claims.get("scope", String.class);

        return stringToScopeListConverter.convert(strScopes);
    }

}
