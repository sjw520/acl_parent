package com.atguigu.security.security;

import com.atguigu.utils.utils.R;
import com.atguigu.utils.utils.ResponseUtil;
import jdk.nashorn.internal.parser.Token;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class TokenLogoutHandler implements LogoutHandler {

    private TokenManager manager;
    private RedisTemplate redisTemplate;
    public TokenLogoutHandler(TokenManager tokenManager,RedisTemplate redisTemplate){
        this.manager = tokenManager;
        this.redisTemplate = redisTemplate;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse httpServletResponse, Authentication authentication) {
        //从header里面获取到token
        //token不为空，移除token，从redis删除token
        String token = request.getHeader("token");
        if(token!=null){
            manager.remove(token);
            //从token中获取用户名
            String username = manager.getUserInfoFromToken(token);
            redisTemplate.delete(username);
        }
        ResponseUtil.out(httpServletResponse, R.ok());
    }
}
