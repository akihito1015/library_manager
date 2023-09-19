package com.example.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	@Override
	protected void configure(HttpSecurity http) throws Exception {
	    // 認可の設定
	    http.authorizeRequests()
	        .antMatchers("/loginForm").permitAll() // /loginFormは、全ユーザからのアクセスを許可
	        .anyRequest().authenticated(); // 許可した項目以外は、認証を求める
	    
	    http.formLogin()
        .loginProcessingUrl("/login") // ログイン処理のパス
        .loginPage("/loginForm") // ログインページの指定
        .usernameParameter("email") // ログインページのメールアドレス
        .passwordParameter("password") // ログインページのパスワード
        .defaultSuccessUrl("/library", true) // ログイン成功後のパス
        .failureUrl("/loginForm?error"); 
	    
	    http.logout()
        .logoutUrl("/logout") //ログアウト処理のパス
        .logoutSuccessUrl("/loginForm"); //ログアウト成功後のパス
	}
	    
	    @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	}
}