package oauthserver.repository;

import oauthserver.domain.model.OAuthFlowCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuthFlowCacheRepository extends JpaRepository<OAuthFlowCache, Long> {
    public Optional<OAuthFlowCache> findByFlowCookie (String flowCookie);
    public Optional<OAuthFlowCache> findByAuthCode (String authCode);
}
