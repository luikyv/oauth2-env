package oauthserver.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import oauthserver.constants.CodeChallengeMethod;
import oauthserver.constants.GrantType;
import oauthserver.constants.ResponseType;
import oauthserver.constants.Scope;
import oauthserver.domain.model.Client;
import oauthserver.domain.model.User;
import oauthserver.domain.payload.AccessTokenResponse;
import oauthserver.domain.payload.ClientPayload;
import oauthserver.domain.model.OAuthFlowCache;
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
import org.springframework.web.util.UriComponentsBuilder;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.util.List;
import java.util.UUID;

@Controller
@AllArgsConstructor
@Slf4j
public class OAuthController {

    // Constants
    private static final String FLOW_ID_COOKIE = "flow_id";
    private static final Integer FLOW_ID_COOKIE_EXPIRE_TIME_SECONDS = 300;
    private static final Integer AUTH_CODE_LENGTH = 30;

    // Services
    private final UserService userService;
    private final OAuthFlowCacheService oauthFlowCacheService;
    private final ClientService clientService;
    private final PckeService pckeService;
    private final TokenService tokenService;

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

        // Create an id to the flow and set a cookie the response
        String flowId = UUID.randomUUID().toString();
        log.info("Flow id: {}", flowId);
        Cookie flowCookie = new Cookie(OAuthController.FLOW_ID_COOKIE, flowId);
        flowCookie.setMaxAge(OAuthController.FLOW_ID_COOKIE_EXPIRE_TIME_SECONDS);
        response.addCookie(flowCookie);

        // Save the information associated to this flow
        String authCode = RandomStringUtils.random(OAuthController.AUTH_CODE_LENGTH, true, true);
        OAuthFlowCache oauthFlowCache = OAuthFlowCache
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
        this.oauthFlowCacheService.saveFlowRecord(oauthFlowCache);

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
            @CookieValue(value = OAuthController.FLOW_ID_COOKIE, defaultValue = "") String flowCookie
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
        OAuthFlowCache oAuthFlowCache;
        try {
            oAuthFlowCache = this.oauthFlowCacheService.getFlowRecord(flowCookie);
        } catch (OAuthFlowCacheRecordNotFoundException e) {
            log.info("OAuth flow record not found");
            model.addAttribute(
                    "errorMessage",
                    "No cookie associated to the flow"
            );
            return new ModelAndView("error", model);
        }
        // Link user to the flow
        oAuthFlowCache.setUser(this.userService.getUser(userCredentials.getUsername()));
        this.oauthFlowCacheService.saveFlowRecord(oAuthFlowCache);

        String redirectUri = UriComponentsBuilder
                .fromUriString(oAuthFlowCache.getClient().getRedirectUri())
                .queryParam("code", oAuthFlowCache.getAuthCode())
                .queryParam("state", oAuthFlowCache.getState())
                .build().toUriString();
        return new ModelAndView("redirect:" + redirectUri, model);
    }

    @SneakyThrows
    @PostMapping("/login") @ResponseBody
    public AccessTokenResponse performLogin(
            @RequestParam("grant_type") GrantType grantType,
            @RequestParam String code,
            @RequestParam("code_verifier") String codeVerifier,
            @RequestParam("client_id") String clientId,
            @RequestParam("client_secret") String clientSecret
    ) {
        //Validate the client's credentials
        boolean areCredentialsValid = false;
        try {
            areCredentialsValid = this.clientService.validateCredentials(clientId, clientSecret);
        } catch (ClientNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Client doesn't exist");
        }
        if(!areCredentialsValid) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid credentials");
        }

        // Validate PCKE
        boolean isChallengeValid = false;
        try {
            isChallengeValid = this.pckeService.validateFlow(codeVerifier, code);
        } catch (OAuthFlowCacheRecordNotFoundException e) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid code");
        }
        if(!isChallengeValid) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "PCKE challenge failed");
        }

        // Load the auth flow
        OAuthFlowCache oAuthFlowCache = this.oauthFlowCacheService.getFlowRecordByAuthCode(code);

        // TODO
        return this.tokenService.buildAccessTokenResponse();
    }
}
