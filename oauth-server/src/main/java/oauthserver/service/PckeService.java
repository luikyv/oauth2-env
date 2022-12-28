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


    /**
     * Generate the hash of <code>codeVerifier</code>.
     *
     * @param codeVerifier
     *          Plain text code that will be hashed.
     * @param codeChallengeMethod
     *          Function to be used to hash the <code>codeChallenge</code>.
     * @return Hash of <code>codeVerifier</code>.
     */
    public String generateCodeChallenge(String codeVerifier, CodeChallengeMethod codeChallengeMethod) {
        byte[] hashedCodeVerifierBytes = codeChallengeMethod.getHashFunction()
                .hashString(codeVerifier, StandardCharsets.UTF_8).asBytes();
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hashedCodeVerifierBytes);
    }

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
        return this.generateCodeChallenge(codeVerifier, codeChallengeMethod).equals(codeChallenge);
    }
}
