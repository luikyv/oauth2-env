package oauthserver.controller;

import io.swagger.v3.oas.annotations.Operation;
import lombok.AllArgsConstructor;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import oauthserver.configuration.Constant;
import oauthserver.domain.dto.*;
import oauthserver.enumerations.*;
import oauthserver.domain.model.Client;
import oauthserver.domain.model.User;
import oauthserver.domain.model.OAuthFlowSession;
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

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.Size;
import java.security.Principal;
import java.util.List;

@Controller
@AllArgsConstructor
@Slf4j
public class OAuthController {

    // Services
    private final UserService userService;
    private final OAuthFlowSessionService oauthFlowSessionService;
    private final ClientService clientService;
    private final OAuthService oAuthService;

    @Operation(summary = "Register a client")
    @PostMapping("/client") @ResponseBody
    public void createClient(@Valid @RequestBody ClientDTO client) {
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
            return ViewPage.ERROR_PAGE.getName();
        }
        log.info("Client with id {} was found", clientId);
        if(!client.getRedirectUri().equals(redirectUri)) {
            log.info("Redirect uri {} doesn't match the one registered", redirectUri);
            model.addAttribute(
                    "errorMessage",
                    "The redirect uri doesn't match the one registered by the Client"
            );
            return ViewPage.ERROR_PAGE.getName();
        }

        // Create a cookie specific to the current flow
        String flowId = this.oAuthService.addFlowCookie(response);

        // Save the information associated to this flow
        String authCode = RandomStringUtils.random(Constant.AUTH_CODE_LENGTH, true, true);
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

        return ViewPage.LOGIN_PAGE.getName();
    }

    @Operation(summary = "Register new user")
    @PostMapping("/signup")
    public String registerUser(
            @ModelAttribute UserDTO userDTO
    ) {
        log.info("Register new user");
        this.userService.createUser(
                User.builder().username(userDTO.getUsername()).name(userDTO.getName()).build(),
                userDTO.getPassword()
        );
        log.info("Render login page");
        return ViewPage.LOGIN_PAGE.getName();
    }

    @Operation(summary = "Log in the user")
    @PostMapping("/login")
    @SneakyThrows
    public ModelAndView performLogin(
            @ModelAttribute UserCredentials userCredentials,
            ModelMap model,
            @CookieValue(value = Constant.FLOW_ID_COOKIE, defaultValue = "") String flowCookie
    ) {
        log.info("The user: {} is trying to login", userCredentials.getUsername());

        // Cannot process a request without a flow associated to it
        if(flowCookie.isBlank()) {
            model.addAttribute(
                    "errorDescription",
                    "No cookie associated to the flow"
            );
            log.info("No flow cookie found");
            return new ModelAndView(ViewPage.ERROR_PAGE.getName(), model);
        }

        // Check the user's credentials
        boolean areCredentialsValid = false;
        try {
            areCredentialsValid = this.userService.validateCredentials(
                    userCredentials.getUsername(),
                    userCredentials.getPassword()
            );
        } catch (UserNotFoundException e) {
            log.info("The user: {} doesn't exist", userCredentials.getUsername());
            return new ModelAndView(ViewPage.SIGNUP_PAGE.getName(), model);
        }
        // Display the error to the user if his credentials are invalid
        // and let him try again
        if(!areCredentialsValid) {
            log.info("Invalid credentials");
            model.addAttribute("error", true);
            return new ModelAndView(ViewPage.LOGIN_PAGE.getName(), model);
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
            return new ModelAndView(ViewPage.ERROR_PAGE.getName(), model);
        }

        // Link user to the flow
        oAuthFlowSession.setUser(this.userService.getUser(userCredentials.getUsername()));
        this.oauthFlowSessionService.saveFlowRecord(oAuthFlowSession);

        log.info("Redirect user to the client uri");
        String redirectUri = this.oAuthService.buildRedirectUri(oAuthFlowSession);
        return new ModelAndView("redirect:" + redirectUri, model);
    }

    @Operation(summary = "Retrieve access token with the authorization code")
    @SneakyThrows
    @PostMapping("/token") @ResponseBody
    public AccessTokenResponse getToken(
            @RequestParam("grant_type") GrantType grantType,
            @RequestParam String code,
            @RequestParam("code_verifier") String codeVerifier,
            Principal client
    ) {
        log.info("The client: {} is trying to get a token", client.getName());

        OAuthFlowSession oAuthFlowSession;
        try {
            oAuthFlowSession = this.oauthFlowSessionService.getFlowRecordByAuthCode(code);
        } catch (OAuthFlowCacheRecordNotFoundException e) {
            log.info("Auth code doesn't exist");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid code");
        }

        // The code can be used only once
        if(oAuthFlowSession.isCodeAlreadyUsed()) {
            log.info("Authorization code already used");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authorization code already used");
        }
        oAuthFlowSession.setCodeAlreadyUsed(true);
        this.oauthFlowSessionService.saveFlowRecord(oAuthFlowSession);

        // Check if the client asking for token is the one who started the flow
        if(!client.getName().equals(oAuthFlowSession.getClient().getId())) {
            log.info("Client is trying to use an authorization code from another client");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Authorization code already used");
        }

        log.info("Validate PCKE");
        boolean isChallengeValid = this.oAuthService.validatePckeSession(codeVerifier, oAuthFlowSession);
        if(!isChallengeValid) {
            log.info("Code verifier does not match the code challenge");
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "PCKE challenge failed");
        }

        log.info("Responding with token");
        return this.oAuthService.buildAccessTokenResponse(oAuthFlowSession);
    }

    @Operation(summary = "Information about the access token and its validity")
    @PostMapping("/token_info") @ResponseBody
    public AccessTokenIntrospectionResponse tokenIntrospection(
            @RequestParam String token,
            Principal client
    ) {

        AccessTokenIntrospectionResponse accessTokenIntrospectionResponse = this.oAuthService.getAccessTokenInformation(token);
        if(!accessTokenIntrospectionResponse.getClientId().equals(client.getName())) {
            log.info("The client in the token doesn't match the one requesting information");
            throw new ResponseStatusException(
                    HttpStatus.BAD_REQUEST,
                    "The client in the token doesn't match the one requesting information"
            );
        }

        log.info("Responding with information about the access token");
        return this.oAuthService.getAccessTokenInformation(token);
    }

    @Operation(summary = "Retrieve user information")
    @GetMapping("/user_info") @ResponseBody
    public UserInfoResponse getUserInfo(HttpServletRequest request) {
        String accessToken = request.getHeader(Constant.AUTHORIZATION_HEADER).substring(Constant.BEARER_PREFIX.length());
        log.info("Responding with user information");
        return this.oAuthService.getUserInfo(accessToken);
    }

    @Operation(summary = "Generate a code challenge by hashing the code verifier")
    @GetMapping("/code_challenge") @ResponseBody
    public String generatePckeCodeChallenge(
            @RequestParam("code_verifier") @Size(min = 43, max = 128) String codeVerifier,
            @RequestParam("code_challenge_method") CodeChallengeMethod codeChallengeMethod
    ) {
        log.info("Generate code challenge");
        return this.oAuthService.generateCodeChallenge(codeVerifier, codeChallengeMethod);
    }

    @GetMapping("/homepage")
    public String getHomepage() {
        return "homepage";
    }
}
