package oauthserver.service;

import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import oauthserver.enumerations.CodeChallengeMethod;
import oauthserver.domain.model.OAuthFlowSession;
import oauthserver.service.exceptions.OAuthFlowCacheRecordNotFoundException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * This class performs all the activities we need concerning PCKE.
 */
@Service
@AllArgsConstructor
public class PckeService {

    private final OAuthFlowSessionService oAuthFlowSessionService;

    /**
     * We verify if the hash of <code>codeVerifier</code> matches <code>codeChallenge</code>.
     *
     * @param codeVerifier
     *          Plain text code that will be hashed and compared to the codeChallenge provided by the client.
     * @param codeChallenge
     *          Hashed code that the client provided at the beginning of the oauth flow.
     * @param codeChallengeMethod
     *          It indicates which hash function generated the <code>codeChallenge</code>.
     * @return a boolean indicating if the challenge was successful.
     */
    public boolean verifyChallenge(String codeVerifier, String codeChallenge, CodeChallengeMethod codeChallengeMethod) {
        byte[] hashedCodeVerifierBytes = codeChallengeMethod.getHashFunction()
                .hashString(codeVerifier, StandardCharsets.UTF_8).asBytes();
        String hashedCodeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeVerifierBytes);
        return hashedCodeVerifier.equals(codeChallenge);
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
        return verifyChallenge(codeVerifier, oAuthFlowSession.getCodeChallenge(), oAuthFlowSession.getCodeChallengeMethod());
    }
}
