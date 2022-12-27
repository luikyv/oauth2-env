package oauthserver.service;

import oauthserver.domain.model.OAuthFlowSession;
import oauthserver.repository.OAuthFlowSessionRepository;
import oauthserver.service.exceptions.OAuthFlowCacheRecordNotFoundException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class OAuthFlowSessionService {
    private final OAuthFlowSessionRepository oauthFlowSessionRepository;

    @Autowired
    public OAuthFlowSessionService(OAuthFlowSessionRepository oauthFlowSessionRepository) {
        this.oauthFlowSessionRepository = oauthFlowSessionRepository;
    }

    public OAuthFlowSession saveFlowRecord(OAuthFlowSession oauthFlowSession) {
        return this.oauthFlowSessionRepository.save(oauthFlowSession);
    }

    public OAuthFlowSession getFlowRecord(String flowCookie) throws OAuthFlowCacheRecordNotFoundException {
        return this.oauthFlowSessionRepository.findByFlowCookie(flowCookie).orElseThrow(OAuthFlowCacheRecordNotFoundException::new);
    }

    public OAuthFlowSession getFlowRecordByAuthCode(String authCode) throws OAuthFlowCacheRecordNotFoundException {
        return this.oauthFlowSessionRepository.findByAuthCode(authCode).orElseThrow(OAuthFlowCacheRecordNotFoundException::new);
    }
}
