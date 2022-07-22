package server.jwt.example.filter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    // need to calling the authentication manager to authenticate the user
    private final AuthenticationManager authenticationManager;

    @Autowired
    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    // 사용자가 로그인할때 해당 CustomAuthenticationFilter를 거쳐서 , 실제로 로그인을 과정을 수행하고, 존재하는 사용자인지 확인한다.
    // need tot call the authentication manager to authenticate the user
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {

        // also can use the object Mapper and then grab the information we need from the request
        String username = request.getParameter("username");
        String password = request.getParameter("password");

        log.info("username: {}", username); log.info("password: {}", password);

        // need to create an object of username password authentication token
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(username, password);

        // in this class, just grabbing the information that is already coming with the request
        // and then pass it into the username password authentication token
        // And then we call authentication manager to authenticate the user


        // this return will be going to UserDetailServiceImpl.loadUserByUsername() to check if the user is in the database or authenticate the user
        return authenticationManager.authenticate(authenticationToken);



    }

    // 로그인에 성공하고 나서 처리하는 filter
    // 로그인에 성공할때마다 Access Token 과 Refresh Token을 건네주려고 한다.
    // whenever the login is successful in which case the method will be called, then we had to send in the Access Token and Refresh Token.
    // to user headers or and the response or something
    // where need to do generate the token and then send that token over to the user
    // in response, going to just pass in the token that we need to send to the user
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authentication) throws IOException, ServletException {
        // need to have some sort of way to generate the token , sign the token and then send it over to the user
        // using library for make the token (JWT)

        // to get the user that's been successfully logged in, we can define a user
        // so  that's the user coming from spring security
        // so that's not the user will define in our domain, as you can see here, it's coming from org.springframework.security.core.userdetails.UserDetails
        User user = (User) authentication.getPrincipal();

        // we can grab information from that logged in user to create the json web token
        // define algorithm , we cas see that this is coming from the library that we just added
        Algorithm algorithm = Algorithm.HMAC256("secret".getBytes());


        // 여기서의 user는 domain에서 만든 user가 아니라 userDetails이다. 주의하자.
        String access_token = JWT.create()
                .withSubject(user.getUsername()) // subject can be really any String that we want , So that can be like , the user Id or the username or something unique about the user, so that we can identify the user by that specific token
                .withExpiresAt(new Date(System.currentTimeMillis() + 10 * 60 * 1000)) // going to be one min, because it's a token that's going to have very short time to live so that they can give us the refresh token , and server give client a new token
                .withIssuer(request.getRequestURI().toString()) // say like company name or the author of this token // SimpleGrantedAuthority 클래스는 String으로 이루어져 있었다. token claim에 저장할때는 GrantedAuthority 형태로 저장하고자 한다.
                .withClaim("roles" , user.getAuthorities().stream().map(GrantedAuthority::getAuthority).collect(Collectors.toList())) // authorities or roles that we put in for that specific user
                .sign(algorithm);

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
                .withSubject(user.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis() + 30 * 60 * 1000)) // going to give this more time, give this a week or a day
                .withIssuer(request.getRequestURI().toString()) // we don't need to pass roles
                .sign(algorithm);

        // we are going to return both tokens to the user
        // instead of setting headers here, want to actually send something in the response body
        //response.setHeader("access_token" , access_token);
        //response.setHeader("refresh_token" , refresh_token);

        Map<String , String> tokens = new HashMap<>();
        tokens.put("access_token" , access_token);
        tokens.put("refresh_token" , refresh_token);
        response.setContentType(APPLICATION_JSON_VALUE);
        new ObjectMapper().writeValue(response.getOutputStream(), tokens); // that's going to return everything in the body


    }
}
