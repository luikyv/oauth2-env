package oauthserver.service;

import lombok.AllArgsConstructor;
import oauthserver.domain.model.User;
import oauthserver.domain.dto.UserCredentials;
import oauthserver.repository.UserRepository;
import oauthserver.service.exceptions.UserNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {
    private UserRepository userRepository;
    private PasswordEncoder passwordEncoder;


    public User createUser(User user, String password) {
        user.setHashedPassword(this.passwordEncoder.encode(password));
        return this.userRepository.save(user);
    }

    public User getUser(String username) throws UserNotFoundException {
        return this.userRepository.findByUsername(username).orElseThrow(UserNotFoundException::new);
    }

    public boolean validateCredentials(String username, String password) throws UserNotFoundException {
        User user = this.getUser(username);
        return passwordEncoder.matches(password, user.getHashedPassword());
    }
}
