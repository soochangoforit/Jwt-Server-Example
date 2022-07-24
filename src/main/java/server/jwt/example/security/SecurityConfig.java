package server.jwt.example.security;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import server.jwt.example.filter.CustomAuthenticationFilter;
import server.jwt.example.filter.CustomAuthorizationFilter;
import server.jwt.example.manager.CustomAuthenticationManager;
import server.jwt.example.service.JwtService;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true)
public class SecurityConfig {

    private final UserDetailsService userDetailsService;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final CustomAuthenticationManager customAuthenticationManager;
    private final JwtService jwtService;




    //  1. UserDetailsService를 담당하는 bean을 넣어주고 ,DB에 있는 암호화된 비밀번호와 비교하기 위해 Encoder 넣어준다.
    // https://blog.naver.com/PostView.naver?blogId=h850415&logNo=222755455272&parentCategoryNo=&categoryNo=37&viewDate=&isShowPopularPosts=true&from=search
//    @Override
//    protected SecurityFilterChain  configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.userDetailsService(userDetailsService).passwordEncoder(bCryptPasswordEncoder);
//    }

    // get authenticationManager()






    // todo : 5번
    @Bean
    protected SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        // /login (POST) is coming from the CustomAuthenticationFilter , let's see UsernamePasswordAuthenticationFilter
        // go inside there AntPathRequestMatcher is defined like "/login" , POST
        // but we can change it to any other path we want

        // as you can see, in this configure , we mush be logged in for using application service

        // to change login url
        // this CustomAuthenticationFilter extending UsernamePasswordAuthenticationFilter
        // we can actually override this with our own custom autntication filter
        CustomAuthenticationFilter customAuthenticationFilter = new CustomAuthenticationFilter(customAuthenticationManager,jwtService);
        customAuthenticationFilter.setFilterProcessesUrl("/api/login"); // we can not use loginProcessingUrl because it's defined in UsernamePasswordAuthenticationFilter because of jwt


        http.csrf().disable()
        .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        .and()
        .authorizeRequests().antMatchers("/api/login" , "/api/token/refresh").permitAll() //this login path is not defined in our resources , we don't have anything log in here
        .antMatchers(GET, "/api/users/**").hasAnyAuthority("ROLE_USER")
        .antMatchers(POST,"/api/user/save/**" , "/api/writeTest").hasAnyAuthority("ROLE_USER")
        .anyRequest().authenticated()
        .and()
        .addFilter(customAuthenticationFilter) // check id or password for authentication then response tokens to user
        // this filter should be comes before the other filters, beacuse we need to intercept every request before any other filters
       //  왜 UsernamePasswordAuthenticationFilter 이전에 CustomAuthenticationFilter를 넣어야 하는지 생각해봤는데
        //  CustomAuthenticationFilter에서 처음에 login 혹은 token/refresh에 대해서 아무런 작업을 하지 않고 그냥 넘겨버린다.
        //  그대로 넘겨버리고, filterChain을 타도록 하였다. 로그인을 하고자 하는 요청에 대해서 먼저 패스를 시키도록 구현하겼기 때문에, 실질적으로 로그인 처리를 담당한느 usernamePasswordAuthenticationFilter 보다 먼저 실행이 되도록 구현하였다.
        //.addFilterBefore(new CustomAuthorizationFilter(customAuthenticationManager) , UsernamePasswordAuthenticationFilter.class);
                .addFilter(new CustomAuthorizationFilter(customAuthenticationManager));

        return http.build();
    }

    @Bean
    public WebSecurityCustomizer webSecurityCustomizer() {
        return (web) -> web.ignoring().antMatchers("/static/**");
    }
}
