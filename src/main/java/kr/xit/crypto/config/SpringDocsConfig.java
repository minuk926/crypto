package kr.xit.crypto.config;

import java.util.*;

import org.apache.commons.lang3.*;
import org.springdoc.core.*;
import org.springframework.beans.factory.annotation.*;
import org.springframework.context.annotation.*;

import io.swagger.v3.oas.models.*;
import io.swagger.v3.oas.models.info.*;
import io.swagger.v3.oas.models.security.*;
import io.swagger.v3.oas.models.servers.*;

@Configuration
public class SpringDocsConfig {
    @Value("${server.port}")
    private int SERVER_PORT;
    @Value("${server.http:0}")
    private int HTTP_PORT;
    @Value("${app.swagger-url:}")
    private String swaggerUrl;
    
    @Bean
    public OpenAPI openAPI(
        @Value("${springdoc.version:v1}") String version,
        @Value("${app.desc:암호화모듈}") String desc,
        @Value("${spring.application.name:}") String name,
        @Value("${spring.profiles.active:local}") String active) {

        Info info = new Info()
            .title(String.format("%s : %s 서버( %s )", desc, name, active))  // 타이틀
            .version(version)           // 문서 버전
            .description("잘못된 부분이나 오류 발생 시 바로 말씀해주세요.") // 문서 설명
            .contact(new Contact()      // 연락처
                .name("관리자")
                .email("admin@xit.co.kr"));
                //.url("http://www.xerotech.co.kr/"));

        // https enabled
        List<Server> servers = new ArrayList<>();
        if(HTTP_PORT != 0){
            String httpUrl = ObjectUtils.isNotEmpty(swaggerUrl)? swaggerUrl : String.format("http://localhost:%d", HTTP_PORT);
            String httpsUrl = ObjectUtils.isNotEmpty(swaggerUrl)? swaggerUrl : String.format("https://localhost:%d", SERVER_PORT);
            servers.add(new Server().url(httpUrl).description(name + "(" + active + ")"));
            servers.add(new Server().url(httpsUrl).description(name + "(" + active + ")"));
        }else {
            String httpUrl = ObjectUtils.isNotEmpty(swaggerUrl)? swaggerUrl : String.format("http://localhost:%d", SERVER_PORT);
            servers.add(new Server().url(httpUrl).description(name + "(" + active + ")"));
        }

        // Security 스키마 설정
        SecurityScheme securityScheme = new SecurityScheme()
            .type(SecurityScheme.Type.HTTP)
            .scheme("bearer")
            .bearerFormat("JWT")
            .in(SecurityScheme.In.HEADER)
            // .name(HttpHeaders.AUTHORIZATION);
            .name("Authorization");

        SecurityRequirement securityRequirement = new SecurityRequirement().addList("bearerAuth");

        return new OpenAPI()
            // Security 인증 컴포넌트 설정
            .components(new Components().addSecuritySchemes("bearerAuth", securityScheme))
            .components(new Components().addSecuritySchemes("bearerAuth", securityScheme))
            // API 마다 Security 인증 컴포넌트 설정
            //.addSecurityItem(new SecurityRequirement().addList("JWT"))
            .security(Collections.singletonList(securityRequirement))
            .info(info)
            .servers(servers);
    }

    @Bean
    public GroupedOpenApi authentification() {
        return GroupedOpenApi.builder()
            .group("1. ARIA GCM crypto cipher Test")
            .pathsToMatch(
                "/**"
            )
            .build();
    }
}
