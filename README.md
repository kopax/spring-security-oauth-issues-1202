Issue [#1202](https://github.com/spring-projects/spring-security-oauth/issues/1202)
=============

I want to request resource data asynchronously.

These are my endpoints : 

An __anonymous user__ should be able to access only these endpoints

- http://localhost:8080/login
- http://localhost:8080/logout
- http://localhost:8080/ping

An __authenticated user__ with `ROLE_USER` should be able to access only these endpoints

- http://localhost:8080/oauth/authorize
- http://localhost:8080/oauth/token

An __authenticated user using a jwt__ can access these endpoints

- http://localhost:8080/**
- http://localhost:8080/roles

I am executing a list of request to a OAuth secured endpoint in two modes:

- synchronously
- asynchronously

Reproduction
------------

You will need two project, the spring backend and a nodejs rest client: 

Requirement:

- Java JDK 8
- Node 4 or later
- Npm 4 or later

1. Clone the project

        mkdir -p ~/tmp && cd ~/tmp && git clone https://github.com/kopax/spring-security-oauth-issues-1202 && cd spring-security-oauth-issues-1202

2. start the server

        ./gradlew build --info && java -jar $(find build/libs -name "*.jar" -type f | xargs ls -tr | tail -1) --spring.profiles.active=default

3. Open a new terminal and clone the client test project

        mkdir -p ~/tmp && cd ~/tmp && git clone git@github.com:kopax/spring-security-oauth-issues-1202-client.git && cd spring-security-oauth-issues-1202-client && npm install
        
4. Run the client test synchronously (always succeed)

        npm run roles
        # this will prompt for credential which are already set for you, just press enter till the end
        
5. Run the client test asynchronously (mostly will fail)
    
        npm run roles
        # this will prompt for credential which are already set for you
        # press enter till the question "ASYNC MODE" where you MUST choose "YES"
        
6. Clean the reproduction

        rm -rf ~/tmp 
 
Expected
--------

http status code `200` 

Result
------

```bash
Handling error: DuplicateKeyException, PreparedStatementCallback; SQL [insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?)]; Unique index or primary key violation: "PRIMARY_KEY_D ON PUBLIC.OAUTH_ACCESS_TOKEN(AUTHENTICATION_ID) VALUES ('b762270ce877e5b49c8f9305e3eb0ab1', 14)"; SQL statement:
insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?) [23505-194]; nested exception is org.h2.jdbc.JdbcSQLException: Unique index or primary key violation: "PRIMARY_KEY_D ON PUBLIC.OAUTH_ACCESS_TOKEN(AUTHENTICATION_ID) VALUES ('b762270ce877e5b49c8f9305e3eb0ab1', 14)"; SQL statement:
insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?) [23505-194]
org.springframework.dao.DuplicateKeyException: PreparedStatementCallback; SQL [insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?)]; Unique index or primary key violation: "PRIMARY_KEY_D ON PUBLIC.OAUTH_ACCESS_TOKEN(AUTHENTICATION_ID) VALUES ('b762270ce877e5b49c8f9305e3eb0ab1', 14)"; SQL statement:
insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?) [23505-194]; nested exception is org.h2.jdbc.JdbcSQLException: Unique index or primary key violation: "PRIMARY_KEY_D ON PUBLIC.OAUTH_ACCESS_TOKEN(AUTHENTICATION_ID) VALUES ('b762270ce877e5b49c8f9305e3eb0ab1', 14)"; SQL statement:
insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?) [23505-194]
	at org.springframework.jdbc.support.SQLErrorCodeSQLExceptionTranslator.doTranslate(SQLErrorCodeSQLExceptionTranslator.java:239)
	at org.springframework.jdbc.support.AbstractFallbackSQLExceptionTranslator.translate(AbstractFallbackSQLExceptionTranslator.java:73)
	at org.springframework.jdbc.core.JdbcTemplate.execute(JdbcTemplate.java:655)
	at org.springframework.jdbc.core.JdbcTemplate.update(JdbcTemplate.java:876)
	at org.springframework.jdbc.core.JdbcTemplate.update(JdbcTemplate.java:937)
	at org.springframework.jdbc.core.JdbcTemplate.update(JdbcTemplate.java:942)
	at org.springframework.security.oauth2.provider.token.store.JdbcTokenStore.storeAccessToken(JdbcTokenStore.java:148)
	at org.springframework.security.oauth2.provider.token.DefaultTokenServices.createAccessToken(DefaultTokenServices.java:122)
	at org.springframework.security.oauth2.provider.token.AbstractTokenGranter.getAccessToken(AbstractTokenGranter.java:70)
	at org.springframework.security.oauth2.provider.token.AbstractTokenGranter.grant(AbstractTokenGranter.java:65)
	at org.springframework.security.oauth2.provider.CompositeTokenGranter.grant(CompositeTokenGranter.java:38)
	at org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer$4.grant(AuthorizationServerEndpointsConfigurer.java:561)
	at org.springframework.security.oauth2.provider.endpoint.TokenEndpoint.postAccessToken(TokenEndpoint.java:132)
	at sun.reflect.NativeMethodAccessorImpl.invoke0(Native Method)
	at sun.reflect.NativeMethodAccessorImpl.invoke(NativeMethodAccessorImpl.java:62)
	at sun.reflect.DelegatingMethodAccessorImpl.invoke(DelegatingMethodAccessorImpl.java:43)
	at java.lang.reflect.Method.invoke(Method.java:498)
	at org.springframework.web.method.support.InvocableHandlerMethod.doInvoke(InvocableHandlerMethod.java:205)
	at org.springframework.web.method.support.InvocableHandlerMethod.invokeForRequest(InvocableHandlerMethod.java:133)
	at org.springframework.web.servlet.mvc.method.annotation.ServletInvocableHandlerMethod.invokeAndHandle(ServletInvocableHandlerMethod.java:97)
	at org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.invokeHandlerMethod(RequestMappingHandlerAdapter.java:827)
	at org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerAdapter.handleInternal(RequestMappingHandlerAdapter.java:738)
	at org.springframework.web.servlet.mvc.method.AbstractHandlerMethodAdapter.handle(AbstractHandlerMethodAdapter.java:85)
	at org.springframework.web.servlet.DispatcherServlet.doDispatch(DispatcherServlet.java:967)
	at org.springframework.web.servlet.DispatcherServlet.doService(DispatcherServlet.java:901)
	at org.springframework.web.servlet.FrameworkServlet.processRequest(FrameworkServlet.java:970)
	at org.springframework.web.servlet.FrameworkServlet.doPost(FrameworkServlet.java:872)
	at javax.servlet.http.HttpServlet.service(HttpServlet.java:661)
	at org.springframework.web.servlet.FrameworkServlet.service(FrameworkServlet.java:846)
	at javax.servlet.http.HttpServlet.service(HttpServlet.java:742)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:231)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.apache.tomcat.websocket.server.WsFilter.doFilter(WsFilter.java:52)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:317)
	at org.springframework.security.web.access.intercept.FilterSecurityInterceptor.invoke(FilterSecurityInterceptor.java:127)
	at org.springframework.security.web.access.intercept.FilterSecurityInterceptor.doFilter(FilterSecurityInterceptor.java:91)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.access.ExceptionTranslationFilter.doFilter(ExceptionTranslationFilter.java:114)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.session.SessionManagementFilter.doFilter(SessionManagementFilter.java:137)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.authentication.AnonymousAuthenticationFilter.doFilter(AnonymousAuthenticationFilter.java:111)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.servletapi.SecurityContextHolderAwareRequestFilter.doFilter(SecurityContextHolderAwareRequestFilter.java:170)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.savedrequest.RequestCacheAwareFilter.doFilter(RequestCacheAwareFilter.java:63)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.authentication.www.BasicAuthenticationFilter.doFilterInternal(BasicAuthenticationFilter.java:215)
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.authentication.logout.LogoutFilter.doFilter(LogoutFilter.java:116)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.header.HeaderWriterFilter.doFilterInternal(HeaderWriterFilter.java:64)
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.context.SecurityContextPersistenceFilter.doFilter(SecurityContextPersistenceFilter.java:105)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.context.request.async.WebAsyncManagerIntegrationFilter.doFilterInternal(WebAsyncManagerIntegrationFilter.java:56)
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)
	at org.springframework.security.web.FilterChainProxy$VirtualFilterChain.doFilter(FilterChainProxy.java:331)
	at org.springframework.security.web.FilterChainProxy.doFilterInternal(FilterChainProxy.java:214)
	at org.springframework.security.web.FilterChainProxy.doFilter(FilterChainProxy.java:177)
	at org.springframework.web.filter.DelegatingFilterProxy.invokeDelegate(DelegatingFilterProxy.java:347)
	at org.springframework.web.filter.DelegatingFilterProxy.doFilter(DelegatingFilterProxy.java:263)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.springframework.web.filter.RequestContextFilter.doFilterInternal(RequestContextFilter.java:99)
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.springframework.web.filter.HttpPutFormContentFilter.doFilterInternal(HttpPutFormContentFilter.java:108)
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.springframework.web.filter.HiddenHttpMethodFilter.doFilterInternal(HiddenHttpMethodFilter.java:81)
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.springframework.session.web.http.SessionRepositoryFilter.doFilterInternal(SessionRepositoryFilter.java:167)
	at org.springframework.session.web.http.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:80)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.springframework.web.filter.CharacterEncodingFilter.doFilterInternal(CharacterEncodingFilter.java:197)
	at org.springframework.web.filter.OncePerRequestFilter.doFilter(OncePerRequestFilter.java:107)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at com.common.servlet.filter.CORSFilter.doFilter(CORSFilter.java:40)
	at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)
	at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)
	at org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:199)
	at org.apache.catalina.core.StandardContextValve.invoke(StandardContextValve.java:96)
	at org.apache.catalina.authenticator.AuthenticatorBase.invoke(AuthenticatorBase.java:478)
	at org.apache.catalina.core.StandardHostValve.invoke(StandardHostValve.java:140)
	at org.apache.catalina.valves.ErrorReportValve.invoke(ErrorReportValve.java:81)
	at org.apache.catalina.core.StandardEngineValve.invoke(StandardEngineValve.java:87)
	at org.apache.catalina.connector.CoyoteAdapter.service(CoyoteAdapter.java:342)
	at org.apache.coyote.http11.Http11Processor.service(Http11Processor.java:803)
	at org.apache.coyote.AbstractProcessorLight.process(AbstractProcessorLight.java:66)
	at org.apache.coyote.AbstractProtocol$ConnectionHandler.process(AbstractProtocol.java:868)
	at org.apache.tomcat.util.net.NioEndpoint$SocketProcessor.doRun(NioEndpoint.java:1459)
	at org.apache.tomcat.util.net.SocketProcessorBase.run(SocketProcessorBase.java:49)
	at java.util.concurrent.ThreadPoolExecutor.runWorker(ThreadPoolExecutor.java:1142)
	at java.util.concurrent.ThreadPoolExecutor$Worker.run(ThreadPoolExecutor.java:617)
	at org.apache.tomcat.util.threads.TaskThread$WrappingRunnable.run(TaskThread.java:61)
	at java.lang.Thread.run(Thread.java:748)
Caused by: org.h2.jdbc.JdbcSQLException: Unique index or primary key violation: "PRIMARY_KEY_D ON PUBLIC.OAUTH_ACCESS_TOKEN(AUTHENTICATION_ID) VALUES ('b762270ce877e5b49c8f9305e3eb0ab1', 14)"; SQL statement:
insert into oauth_access_token (token_id, token, authentication_id, user_name, client_id, authentication, refresh_token) values (?, ?, ?, ?, ?, ?, ?) [23505-194]
	at org.h2.message.DbException.getJdbcSQLException(DbException.java:345)
	at org.h2.message.DbException.get(DbException.java:179)
	at org.h2.message.DbException.get(DbException.java:155)
	at org.h2.index.BaseIndex.getDuplicateKeyException(BaseIndex.java:103)
	at org.h2.mvstore.db.MVSecondaryIndex.checkUnique(MVSecondaryIndex.java:231)
	at org.h2.mvstore.db.MVSecondaryIndex.add(MVSecondaryIndex.java:190)
	at org.h2.mvstore.db.MVTable.addRow(MVTable.java:707)
	at org.h2.command.dml.Insert.insertRows(Insert.java:156)
	at org.h2.command.dml.Insert.update(Insert.java:114)
	at org.h2.command.CommandContainer.update(CommandContainer.java:101)
	at org.h2.command.Command.executeUpdate(Command.java:258)
	at org.h2.jdbc.JdbcPreparedStatement.executeUpdateInternal(JdbcPreparedStatement.java:160)
	at org.h2.jdbc.JdbcPreparedStatement.executeUpdate(JdbcPreparedStatement.java:146)
	at org.springframework.jdbc.core.JdbcTemplate$2.doInPreparedStatement(JdbcTemplate.java:883)
	at org.springframework.jdbc.core.JdbcTemplate$2.doInPreparedStatement(JdbcTemplate.java:876)
	at org.springframework.jdbc.core.JdbcTemplate.execute(JdbcTemplate.java:639)
	... 104 common frames omitted
Socket: [org.apache.tomcat.util.net.NioEndpoint$NioSocketWrapper@4f2cecca:org.apache.tomcat.util.net.NioChannel@486d5308:java.nio.channels.SocketChannel[connected local=/127.0.0.1:8080 remote=/127.0.0.1:39524]], Read from buffer: [0]
Received [GET /roles?organization=kopax&siteServiceIds=6000 HTTP/1.1
accept: application/json
authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOlsibXlhcHAvYXBpIl0sInVzZXJfbmFtZSI6ImFkbWluIiwic2NvcGUiOlsidHJ1c3QiLCJyZWFkIiwid3JpdGUiXSwiZXhwIjoxNTEzMDQ0MDA1LCJhdXRob3JpdGllcyI6WyJST0xFX01BTkFHRVIiLCJST0xFX0FETUlOIiwiUk9MRV9VU0VSIl0sImp0aSI6IjE3YjgxNWNhLTc5NmMtNGI4Ni05YjZjLWY3YzgzMjA0NzczOSIsImNsaWVudF9pZCI6Im15Zmlyc3RhcHAiLCJ1c2VybmFtZSI6ImFkbWluIn0.NQx11bSgHKv3dHYaLydyo7kwqsiydSLTZPvRaSXsXl4
content-type: application/json
cookie: XSRF-TOKEN=d1111657-c1b2-471a-99aa-a338c23dd8b5; JSESSIONID=983615fd-d156-4072-ac18-efd365345036
accept-encoding: gzip,deflate
user-agent: node-fetch/1.0 (+https://github.com/bitinn/node-fetch)
connection: close
Host: localhost:8080

```


Useful information:
===================

Spring server:

- http://localhost:8080/

Security account (cookie):

- username: `admin`
- password: `verysecret`

OAuth account (jwt):

- client_id: `myfirstapp`
- client_secret: `test`
- redirect_uri: `http://localhost:8080/`
- access_token_uri: `http://localhost:8080/oauth/token`
- authorization_uri: `http://localhost:8080/oauth/authorize`
- authorization_grant: `code`
- redirect_uri: `http://localhost:8080`

