package oauthserver.service;

import com.google.common.hash.Hashing;
import lombok.AllArgsConstructor;
import oauthserver.domain.model.OAuthFlowCache;
import oauthserver.service.exceptions.OAuthFlowCacheRecordNotFoundException;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;

@Service
@AllArgsConstructor
public class PckeService {
    private final OAuthFlowCacheService oAuthFlowCacheService;
    public boolean validateFlow(String codeVerifier, String authCode) throws OAuthFlowCacheRecordNotFoundException {
        OAuthFlowCache oAuthFlowCache = oAuthFlowCacheService.getFlowRecordByAuthCode(authCode);
        String hashedCodeVerifier = Hashing.sha256()
                .hashString(codeVerifier, StandardCharsets.UTF_8)
                .toString();
        return hashedCodeVerifier.equals(oAuthFlowCache.getCodeChallenge());
    }
}
