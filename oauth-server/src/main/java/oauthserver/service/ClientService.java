package oauthserver.service;

import lombok.AllArgsConstructor;
import oauthserver.domain.model.Client;
import oauthserver.domain.model.User;
import oauthserver.repository.ClientRepository;
import oauthserver.service.exceptions.ClientNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class ClientService {
    private ClientRepository clientRepository;
    private PasswordEncoder passwordEncoder;

    public Client createClient(Client client, String secret) {
        client.setHashedSecret(this.passwordEncoder.encode(secret));
        return this.clientRepository.save(client);
    }

    public Client getClient(String clientId) throws ClientNotFoundException {
        return this.clientRepository.findById(clientId).orElseThrow(ClientNotFoundException::new);
    }

    public boolean validateCredentials(String clientId, String clientSecret) throws ClientNotFoundException {
        Client client = this.getClient(clientId);
        return passwordEncoder.matches(clientSecret, client.getHashedSecret());
    }
}
