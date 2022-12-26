package oauthserver;

import oauthserver.domain.model.User;
import oauthserver.service.ClientService;
import oauthserver.service.UserService;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;

@SpringBootApplication(exclude = { SecurityAutoConfiguration.class })
public class OauthServerApplication implements CommandLineRunner {

	private final UserService userService;
	private final ClientService clientService;

	public OauthServerApplication(UserService userService, ClientService clientService) {
		this.clientService = clientService;
		this.userService = userService;
	}

	public static void main(String[] args) {
		SpringApplication.run(OauthServerApplication.class, args);
	}

	@Override
	public void run(String... args) {
		this.userService.createUser(
				User.builder().username("admin").build(),
				"1234"
		);
	}

}
