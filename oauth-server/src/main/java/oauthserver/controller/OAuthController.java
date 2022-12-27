package oauthserver.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import oauthserver.configuration.Config;
import oauthserver.enumerations.CodeChallengeMethod;
import oauthserver.enumerations.GrantType;
import oauthserver.enumerations.ResponseType;
import oauthserver.enumerations.Scope;
import oauthserver.domain.model.Client;
import oauthserver.domain.model.User;
import oauthserver.domain.payload.AccessTokenResponse;
import oauthserver.domain.payload.ClientPayload;
import oauthserver.domain.model.OAuthFlowSession;
import oauthserver.domain.payload.UserCredentials;
import oauthserver.service.*;
import oauthserver.service.exceptions.ClientNotFoundException;
import oauthserver.service.exceptions.OAuthFlowCacheRecordNotFoundException;
import oauthserver.service.exceptions.UserNotFoundException;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.List;

@Controller
@AllArgsConstructor
@Slf4j
public class OAuthController {

    // Services
    private final UserService userService;
    private final OAuthFlowSessionService oauthFlowSessionService;
    private final ClientService clientService;
    private final PckeService pckeService;
    private final OAuthService oAuthService;

    @Operation(summary = "Register a client")
    @PostMapping("/client") @ResponseBody
    public void createClient(@Valid @RequestBody ClientPayload client) {
        this.clientService.createClient(
                Client
                        .builder()
                        .id(client.getClientId())
                        .name(client.getName())
                        .description(client.getDescription())
                        .redirectUri(client.getRedirectUri())
                        .build(),
                client.getSecret()
        );
    }

    @Operation(summary = "Start OAuth flow and log in the user")
    @GetMapping("/authorization")
    public String authorize(
            @RequestParam("response_type") ResponseType responseType,
            @RequestParam("client_id") String clientId,
            @RequestParam("redirect_uri") String redirectUri,
            @RequestParam("scopes") List<Scope> scopes,
            @RequestParam("state") String state,
            @RequestParam("code_challenge") String codeChallenge,
            @RequestParam("code_challenge_method") CodeChallengeMethod codeChallengeMethod,
            HttpServletResponse response,
            Model model
    ) {
        // Check if the client exists
        Client client = null;
        try {
            client = this.clientService.getClient(clientId);
        } catch (ClientNotFoundException e) {
            log.info("Client with id {} doesn't exist", clientId);
            model.addAttribute(
                    "errorMessage",
                    "The Client is not registered"
            );
            return "error";
        }
        log.info("Client with id {} was found", clientId);
        if(!client.getRedirectUri().equals(redirectUri)) {
            log.info("Redirect uri {} doesn't match the one registered", redirectUri);
            model.addAttribute(
                    "errorMessage",
                    "The redirect uri doesn't match the one registered by the Client"
            );
            return "error";
        }

        // Create a cookie specific to the current flow
        String flowId = this.oAuthService.addFlowCookie(response);

        // Save the information associated to this flow
        String authCode = RandomStringUtils.random(Config.AUTH_CODE_LENGTH, true, true);
        OAuthFlowSession oauthFlowSession = OAuthFlowSession
                .builder()
                .flowCookie(flowId)
                .client(client)
                .authCode(authCode)
                .codeAlreadyUsed(false)
                .scopes(scopes)
                .state(state)
                .codeChallenge(codeChallenge)
                .codeChallengeMethod(codeChallengeMethod)
                .build();
        this.oauthFlowSessionService.saveFlowRecord(oauthFlowSession);

        return "login";
    }

    @PostMapping("/signup")
    public String registerUser(
            @ModelAttribute UserCredentials userCredentials
    ) {
        this.userService.createUser(
                User.builder().username(userCredentials.getUsername()).build(),
                userCredentials.getPassword()
        );
        return "login";
    }

    @PostMapping("/login")
    @SneakyThrows
    public ModelAndView performLogin(
            @ModelAttribute UserCredentials userCredentials,
            ModelMap model,
            @CookieValue(value = Config.FLOW_ID_COOKIE, defaultValue = "") String flowCookie
    ) {
        log.info("The user: {} is trying to login", userCredentials.getUsername());

        // Cannot process a request without a flow associated to it
        if(flowCookie.isBlank()) {
            model.addAttribute(
                    "errorDescription",
                    "No cookie associated to the flow"
            );
            log.info("No flow cookie found");
            return new ModelAndView("error", model);
        }

        // Check the user's credentials
        boolean areCredentialsValid = false;
        try {
            areCredentialsValid = this.userService.validateCredentials(userCredentials);
        } catch (UserNotFoundException e) {
            log.info("The user: {} doesn't exist", userCredentials.getUsername());
            return new ModelAndView("signup", model);
        }
        // Display the error to the user if his credentials are invalid
        // and let him try again
        if(!areCredentialsValid) {
            log.info("Invalid credentials");
            model.addAttribute("error", true);
            return new ModelAndView("login", model);
        }

        // Load information about the flow
        OAuthFlowSession oAuthFlowSession;
        try {
            oAuthFlowSession = this.oauthFlowSessionService.getFlowRecord(flowCookie);
        } catch (OAuthFlowCacheRecordNotFoundException e) {
            log.info("OAuth flow record not found");
            model.addAttribute(
                    "errorMessage",
                    "No cookie associated to the flow"
            );
            return new ModelAndView("error", model);
        }

        // Link user to the flow
        oAuthFlowSession.setUser(this.userService.getUser(userCredentials.getUsername()));
        this.oauthFlowSessionService.saveFlowRecord(oAuthFlowSession);

        // Redirect user to the client
        String redirectUri = this.oAuthService.buildRedirectUri(oAuthFlowSession);
        return new ModelAndView("redirect:" + redirectUri, model);
    }

    @SneakyThrows
    @PostMapping("/token") @ResponseBody
    public AccessTokenResponse getToken(
            @RequestParam("grant_type") GrantType grantType,
            @RequestParam String code,
            @RequestParam("code_verifier") String codeVerifier,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret
    ) {
        log.info("The client: {} is trying to get a token", clientId);

        // Validate the client's credentials
        boolean areCredentialsValid = false;
        try {
            areCredentialsValid = this.clientService.validateCredentials(clientId, clientSecret);
        } catch (ClientNotFoundException e) {
            log.info("The client: {} doesn't exist", clientId);
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client doesn't exist");
        }
        if(!areCredentialsValid) {
            log.info("Invalid credentials");
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        // Validate PCKE
        boolean isChallengeValid = false;
        try {
            isChallengeValid = this.pckeService.validatePckeSession(codeVerifier, code);
        } catch (OAuthFlowCacheRecordNotFoundException e) {
            log.info("Auth code doesn't exist");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid code");
        }
        if(!isChallengeValid) {
            log.info("PCKE failed");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "PCKE challenge failed");
        }

        log.info("Generating response");
        // Load the auth flow and return access token response
        OAuthFlowSession oAuthFlowSession = this.oauthFlowSessionService.getFlowRecordByAuthCode(code);
        return this.oAuthService.buildAccessTokenResponse(oAuthFlowSession);
    }
}
