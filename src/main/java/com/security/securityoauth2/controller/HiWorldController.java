package com.security.securityoauth2.controller;


import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/security")
public class HiWorldController {


    @Autowired
    private OAuth2AuthorizedClientService authorizedClientService;

    @GetMapping("/login")
    public void login(HttpServletResponse response) throws IOException {
        response.sendRedirect("/oauth2/authorization/google");
    }

    @GetMapping("/hello")
    public String helloWorld() {
        return "Haz sido autenticado con Google satisfactoriamente";
    }

    /**
     * Se debe deshabilitar el endppoints manuales para poder usar issuer-uri
     * y obtener tokens.
     * En caso de que se quiera manejar por sesion, de debe habilitar los endpoints manuales y quitar issuer-uri
     * de las configuraciones
     * @param authentication
     * @return
     */
    @GetMapping("/token")
    public Map<String, String> getTokens(Authentication authentication) {
        if (authentication instanceof OAuth2AuthenticationToken authToken) {
            OAuth2AuthorizedClient client = authorizedClientService
                    .loadAuthorizedClient(
                            authToken.getAuthorizedClientRegistrationId(),
                            authToken.getName()
                    );

            OidcUser oidcUser = (OidcUser) authToken.getPrincipal();

            return Map.of(
                    "id_token", oidcUser.getIdToken().getTokenValue(),
                    "access_token", client.getAccessToken().getTokenValue()
            );
        }
        return Map.of("error", "No se pudo obtener los tokens");
    }



    @GetMapping("/user/data")
    public Map<String, Object> userInfo(@AuthenticationPrincipal OAuth2User principal) {
        Map<String, Object> info = new HashMap<>();
        if (principal != null) {
            info.put("name", principal.getAttribute("name"));
            info.put("email", principal.getAttribute("email"));
            info.put("attributes", principal.getAttributes());
        } else {
            info.put("error", "Usuario no encontrado");
        }
        return info;
    }
}

