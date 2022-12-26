package oauthserver.repository;

import oauthserver.domain.model.Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface ClientRepository extends JpaRepository<Client, String> { }
