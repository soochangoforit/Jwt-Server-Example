package server.jwt.example.api;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;
import server.jwt.example.domain.AppUser;
import server.jwt.example.domain.Role;
import server.jwt.example.security.PrincipalDetails;
import server.jwt.example.service.JwtService;
import server.jwt.example.service.UserService;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.util.*;
import java.util.stream.Collectors;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.FORBIDDEN;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
@Slf4j
public class UserController {

    private final UserService userService;

    private final JwtService jwtService;





    @PostMapping("/write")
    @Secured("ROLE_USER") // 권한이 필요한 부분에 접근시, 어떤 사용자가 해당 요청을 확인했는지 확인하기 위해 @AuthenticationPrincipal은 JwtAuthorizationFilter 에서 set을 통해서 spring security session에 넣어준다.
    public String writeTest(@RequestBody String text, @AuthenticationPrincipal Long id) {

        log.info("writeTest : {}", text);
        log.info("user principal id : {}" , id);

        return text;
    }


    @GetMapping("/users")
    public ResponseEntity<List<AppUser>> getUsers() {
        return ResponseEntity.ok().body(userService.getUsers()); //return 200
    }

    @PostMapping("/users/save")
    public ResponseEntity<AppUser> saveUser(@RequestBody AppUser user) {

        // fromCurrentContext() means localhost:8080
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/user/save").toUriString());
        //HTTP Header에 Location=http://localhost/api/user/save 정보가 들어간다
        return ResponseEntity.created(uri).body(userService.saveUser(user));
    }

    @PostMapping("/role/save")
    public ResponseEntity<Role> saveRole(@RequestBody Role role) {
        URI uri = URI.create(ServletUriComponentsBuilder.fromCurrentContextPath().path("/api/role/save").toUriString());
        return ResponseEntity.created(uri).body(userService.saveRole(role));
    }

    @PostMapping("/role/addtouser")
    public ResponseEntity<?> addRoleToUser(@RequestBody RoleToUserForm form){
        userService.addRoleToUser(form.getUsername(), form.getRoleName());
        return ResponseEntity.ok().build();
    }


    @GetMapping("/token/refresh")
    public void refreshToken(HttpServletRequest request , HttpServletResponse response) throws IOException {
        String authorizationHeader = request.getHeader(AUTHORIZATION);

        if(authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {

            try {

                Map<String, String> tokens = jwtService.getNewAccessTokenWithRefreshToken(request, authorizationHeader, "secret", 10, 60);


//                String refresh_token = authorizationHeader.substring("Bearer ".length()); // just need token without "Bearer"
//                Algorithm algorithm = Algorithm.HMAC256("secret".getBytes()); // use same secret here when we made token
//
//                // we need the alogrithm , the same secre key that we use to edcode the token and then pass that algorithm to the verifier
//                JWTVerifier verifier = JWT.require(algorithm).build(); // this is the verifier that we need to use to verify the token
//
//                // and then now, we can do the decoded token
//                DecodedJWT decodedJWT = verifier.verify(refresh_token); // this is the decoded token
//
//                String username = decodedJWT.getClaim("username").asString(); // get the username from the token
//                AppUser user = userService.getUser(username);
//                String access_token = JWT.create()
//                        .withSubject(user.getId().toString())
//                        .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000))
//                        .withIssuer(request.getRequestURI().toString())
//                        .withClaim("username", user.getUsername())
//                        .withClaim("roles", user.getRoles().stream().map(Role::getAuthority).collect(Collectors.toList()))
//                        .sign(algorithm);
//
//
//
//
//                Map<String, String> tokens = new HashMap<>();
//                tokens.put("access_token", access_token);
//                tokens.put("refresh_token", refresh_token); // 프론트에서 받은 refresh token을 그대로 넣어준다. , refresh 마저 유효기간이 지나면 새롭게 로그인 필요
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getWriter(), tokens);

            } catch (Exception exception) {
                response.setHeader("error", exception.getMessage());
                response.setStatus(FORBIDDEN.value());

                Map<String, String> error = new HashMap<>();
                error.put("error", exception.getMessage());
                response.setContentType(APPLICATION_JSON_VALUE);
                new ObjectMapper().writeValue(response.getOutputStream(), error);

            }

        }else{
            throw new RuntimeException("JWT Token is missing");
        }
    } // end of controller



}

@Data
class RoleToUserForm{
    private String username;
    private String roleName;
}
