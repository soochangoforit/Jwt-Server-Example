package server.jwt.example.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Service;
import server.jwt.example.domain.AppUser;
import server.jwt.example.domain.Role;
import server.jwt.example.security.PrincipalDetails;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class JwtService {

    private final UserService userService;


    public String createAccessToken(HttpServletRequest request, Authentication authentication , String algorithmKey , Integer validMinutes){
        // need to have some sort of way to generate the token , sign the token and then send it over to the user
        // using library for make the token (JWT

        // to get the user that's been successfully logged in, we can define a user
        // so  that's the user coming from spring security
        // so that's not the user will define in our domain, as you can see here, it's coming from principalDetails
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        AppUser user = principalDetails.getAppUser();

        // we can grab information from that logged in user to create the json web token
        // define algorithm , we cas see that this is coming from the library that we just added
        Algorithm algorithm = Algorithm.HMAC256(algorithmKey.getBytes());

        String access_token = JWT.create()
                .withSubject(user.getId().toString()) // subject can be really any String that we want , So that can be like , the user Id or the username or something unique about the user, so that we can identify the user by that specific token
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutes * 60 * 1000)) // going to be one min, because it's a token that's going to have very short time to live so that they can give us the refresh token , and server give client a new token
                .withIssuer(request.getRequestURI().toString()) // say like company name or the author of this token // SimpleGrantedAuthority 클래스는 String으로 이루어져 있었다. token claim에 저장할때는 GrantedAuthority 형태로 저장하고자 한다.
                // need to convert list of granted authorities to list of strings
                .withClaim("username" , user.getUsername())
                .withClaim("roles" ,  principalDetails.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())) // authorities or roles that we put in for that specific user
                .sign(algorithm);


        return access_token;
    }

    public String createRefreshToken(HttpServletRequest request, Authentication authentication , String algorithmKey , Integer validMinutes){

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        AppUser user = principalDetails.getAppUser();

        Algorithm algorithm = Algorithm.HMAC256(algorithmKey.getBytes());

        // 우선 클라이언트는 최초 로그인 성공 시점에 access , refresh token 둘다 받는다.
        // access token으로 계속 요청하다가, 토큰이 expried 되면서, 접근을 하지 못할때 프론트 측에서
        // 빠르게(원할하게) 자신이 가지고 있는 Refresh Token을 가지고, Server에게 보낸다.
        // Server에서 Refresh 토큰이 유효하면 새로운 Access Token을 발급하고 refresh 토큰도 그대로 준다. 클라이언트에게 전송한다.
        // 클라이언트는 Access token을 받으면, 이를 이용해서 원래 요청하고자 했던 요청을 다시 요청을 진행한다.
        // 여기서 의문점은 아니 그럼 그냥 Refresh token 받으면 그걸로 권한 확인해서 하면 되지 않느냐~~, 하지만 Refresh token에는 roles를 넣지 않았다. // refresh 토큰의 목적은 단순히, 권한처리가 아닌 검증에 중점점 둔다.
        // 1:51:40에서 설명 나옴
        // if access token expired, then client going to send the refresh token to the server, and then
        // server is going to take that refresh token, validate it, and then give them another access token
        String refresh_token = JWT.create()
                .withSubject(user.getId().toString()) // subject can be really any String that we want , So that can be like , the user Id or the username or something unique about the user, so that we can identify the user by that specific token
                .withClaim("username" , user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutes * 60 * 1000)) // // going to give this more time, give this a week or a day
                .withIssuer(request.getRequestURI().toString()) // we don't need to pass roles in refresh token
                .sign(algorithm);

        return refresh_token;

    }



    public Map<String , String> getNewAccessTokenWithRefreshToken(HttpServletRequest request , String authorizationHeader , String algorithmKey , Integer validMinutesForAccessToken , Integer validMinutesForRefreshToken) {

        String refresh_token = authorizationHeader.substring("Bearer ".length()); // just need token without "Bearer"
        Algorithm algorithm = Algorithm.HMAC256(algorithmKey.getBytes()); // use same secret here when we made token

        // we need the alogrithm , the same secre key that we use to edcode the token and then pass that algorithm to the verifier
        JWTVerifier verifier = JWT.require(algorithm).build(); // this is the verifier that we need to use to verify the token

        // and then now, we can do the decoded token
        DecodedJWT decodedJWT = verifier.verify(refresh_token); // this is the decoded token

        String username = decodedJWT.getClaim("username").asString(); // get the username from the token
        AppUser user = userService.getUser(username);

        String access_token = JWT.create()
                .withSubject(user.getId().toString())
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutesForAccessToken * 60 * 1000))
                .withIssuer(request.getRequestURI().toString())
                .withClaim("username", user.getUsername())
                .withClaim("roles", user.getRoles().stream().map(Role::getAuthority).collect(Collectors.toList()))
                .sign(algorithm);

        String new_refresh_token = JWT.create()
                .withSubject(user.getId().toString()) // subject can be really any String that we want , So that can be like , the user Id or the username or something unique about the user, so that we can identify the user by that specific token
                .withClaim("username" , user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + validMinutesForRefreshToken * 60 * 1000)) // // going to give this more time, give this a week or a day
                .withIssuer(request.getRequestURI().toString()) // we don't need to pass roles in refresh token
                .sign(algorithm);

        Map<String , String> map = new java.util.HashMap<>();
        map.put("access_token" , access_token);
        map.put("refresh_token" , new_refresh_token);

        return map;

    }


}
