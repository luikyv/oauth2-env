package oauthserver.service;

import oauthserver.domain.model.OAuthFlowCache;
import oauthserver.repository.OAuthFlowCacheRepository;
import oauthserver.service.exceptions.OAuthFlowCacheRecordNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OAuthFlowCacheService {
    private final OAuthFlowCacheRepository oauthFlowCacheRepository;

    @Autowired
    public OAuthFlowCacheService(OAuthFlowCacheRepository oauthFlowCacheRepository) {
        this.oauthFlowCacheRepository = oauthFlowCacheRepository;
    }

    public OAuthFlowCache saveFlowRecord(OAuthFlowCache oauthFlowCache) {
        return this.oauthFlowCacheRepository.save(oauthFlowCache);
    }

    public OAuthFlowCache getFlowRecord(String flowCookie) throws OAuthFlowCacheRecordNotFoundException {
        return this.oauthFlowCacheRepository.findByFlowCookie(flowCookie).orElseThrow(OAuthFlowCacheRecordNotFoundException::new);
    }

    public OAuthFlowCache getFlowRecordByAuthCode(String authCode) throws OAuthFlowCacheRecordNotFoundException {
        return this.oauthFlowCacheRepository.findByAuthCode(authCode).orElseThrow(OAuthFlowCacheRecordNotFoundException::new);
    }
}
