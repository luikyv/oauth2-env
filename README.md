# oauth2-env
In this project we'll build an OAuth environment based on the OAuth 2.1 framework.

## Authorization Grant Flow
In the general scenario, for a private client (the client can stored secrets securely), what happens is the following: A user wants to access an app (client) through his browser (user agent). The app in turn uses the user's resources to perform its activities.

However the user's resources are stored in the ResourceServer. In order to the App access the user's resources, it needs to ask the user to allow it. This grant flow is managed by the AuthServer.

Here below we can see how the flow happens
```mermaid
sequenceDiagram
    participant User
    participant Browser
    participant App
    participant ResourceServer
    participant AuthServer

    User ->> Browser: Access the App
    
    Browser ->> App: Access the App

    App ->> App: PCKE: Generates code verifier and code challenge

    App ->> Browser: Redirect the user to the AuthServer
    Note left of App: The App needs the user's grant
    Note left of App: The code challenge is sent during the redirect

    Browser ->> AuthServer: Get login and consent page
    
    AuthServer ->> Browser: Return login page
    
    Browser ->> User: Display login page
    
    User ->> Browser: Provide credentials
    
    Browser ->>  AuthServer: Inform user's credentials
    
    AuthServer ->> AuthServer: Validate credentials and create session

    AuthServer ->> Browser: Redirect user to app along with auth code

    Browser ->> App: Deliver auth code

    App ->> AuthServer: Get access token.
    Note left of AuthServer: The app provides the auth code, code verifier and the its credentials.

    AuthServer ->> App: Return access token

    App ->> ResourceServer: Get the user's resources.
    Note left of ResourceServer: The app provides the access token.

    ResourceServer ->> ResourceServer: Verify the access token
    Note right of ResourceServer: By asking the AuthServer or locally using its certificate.

    ResourceServer ->> App: Return the user's resources

    App ->> Browser: Return the content the user asked for

    Browser ->> User: Display the content
```

Sequence diagram built using [Mermaid.js](https://mermaid.js.org/)

## API

To access the OpenAPI specification with swagger go to:
http://localhost:8080/swagger-ui.html