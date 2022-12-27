package oauthserver.repository;

import oauthserver.domain.model.OAuthFlowSession;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface OAuthFlowSessionRepository extends JpaRepository<OAuthFlowSession, Long> {
    public Optional<OAuthFlowSession> findByFlowCookie (String flowCookie);
    public Optional<OAuthFlowSession> findByAuthCode (String authCode);
}
