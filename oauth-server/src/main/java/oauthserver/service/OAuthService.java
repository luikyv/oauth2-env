package oauthserver.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauthserver.configuration.Config;
import oauthserver.enumerations.CodeChallengeMethod;
import oauthserver.domain.model.OAuthFlowSession;
import oauthserver.domain.dto.AccessTokenResponse;
import oauthserver.service.exceptions.OAuthFlowCacheRecordNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

@Service
@Slf4j
@AllArgsConstructor
public class OAuthService {

    private final Config config;
    private final OAuthFlowSessionService oAuthFlowSessionService;

    private final TokenService tokenService;
    private final PckeService pckeService;


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
     * More info on oauthserver.service.TokenService::buildAccessTokenResponse
     */
    public AccessTokenResponse buildAccessTokenResponse(OAuthFlowSession oAuthFlowSession) {
        return this.tokenService.buildAccessTokenResponse(oAuthFlowSession);
    }

    /**
     * This method will fetch the information about the current auth session and verify if the codeVerifier
     * matches the codeChallenge.
     *
     * @param codeVerifier
     *          Plain text code that will be compared to the codeChallenge provided by the client.
     * @param authCode
     *          Authorization code generated for the current session.
     *          We use it to fetch the information about the session.
     * @return a boolean indicating if the challenge was successful.
     * @throws OAuthFlowCacheRecordNotFoundException
     *          When the information about the session doesn't exist.
     */
    public boolean validatePckeSession(String codeVerifier, String authCode) throws OAuthFlowCacheRecordNotFoundException {
        OAuthFlowSession oAuthFlowSession = oAuthFlowSessionService.getFlowRecordByAuthCode(authCode);
        return this.pckeService.verifyChallenge(
                codeVerifier,
                oAuthFlowSession.getCodeChallenge(),
                oAuthFlowSession.getCodeChallengeMethod()
        );
    }

    /**
     * More info on oauthserver.service.PckeService::generateCodeChallenge.
     */
    public String generateCodeChallenge(String codeVerifier, CodeChallengeMethod codeChallengeMethod) {
        return this.pckeService.generateCodeChallenge(codeVerifier, codeChallengeMethod);
    }
}
