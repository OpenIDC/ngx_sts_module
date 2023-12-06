[![Build Status](https://github.com/OpenIDC/ngx_sts_module/actions/workflows/build.yml/badge.svg)](https://github.com/OpenIDC/ngx_sts_module/actions/workflows/build.yml)

# ngx_sts_module

A security token exchange module for the NGINX web server which allows for exchanging arbitrary security
tokens by calling into a remote Security Token Service (STS).
For an overview and rationale see the Apache version of this module at:
https://github.com/OpenIDC/mod_sts/blob/master/README.md.

## Quickstart

WS-Trust STS with HTTP Basic authentication and setting the target token in a cookie.

```nginx
       location /sts/wstrust {
        	STSExchange wstrust https://pingfed:9031/pf/sts.wst
				auth=basic&username=wstrust&password=2Federate&applies_to=urn:pingfed&value_type=urn:pingidentity.com:oauth2:grant_type:validate_bearer&token_type=urn:bogus:token&ssl_verify=false;

            STSVariables $source_token $wst_target_token;
            
            proxy_set_header Cookie STS_COOKIE=$wst_target_token;
            proxy_pass http://echo:8080$is_args$args;            
        }
```

OAuth 2.0 Resource Owner Password Credentials based Token Exchange with `client_secret_basic` authentication.

```nginx
        location /sts/ropc {
			STSExchange ropc https://pingfed:9031/as/token.oauth2
				auth=client_secret_basic&client_id=sts0&client_secret=2Federate&username=dummy&ssl_verify=false;
            
            STSVariables $source_token $ropc_target_token;
            
            proxy_set_header Cookie STS_COOKIE=$ropc_target_token;
            proxy_pass http://echo:8080$is_args$args;            
        }
```

OAuth 2.0 Client Credentials based token retrieval with `client_secret_basic` authentication.

```nginx
        location /sts/cc {        
			STSExchange cc https://keycloak:8443/realms/master/protocol/openid-connect/token
				auth=client_secret_basic&client_id=cc_client&client_secret=mysecret&ssl_verify=false;
          
            set $dummy_variable "notempty";
            STSVariables $dummy_variable $cc_target_token;
            
            proxy_set_header Authorization "bearer $cc_target_token";
            proxy_pass http://echo:8080$is_args$args;            
        }
```

OAuth 2.0 Token Exchange with `client_secret_basic` authentication.

```nginx
        location /sts/otx {
			STSExchange otx https://keycloak:8443/auth/realms/master/protocol/openid-connect/token
				auth=client_secret_basic&client_id=otxclient&client_secret=2Federate&ssl_verify=false;

            STSVariables $source_token $otx_target_token;
            
            proxy_set_header Cookie STS_COOKIE=$otx_target_token;
            proxy_pass http://echo:8080$is_args$args;            
        }        
```

## Configuration 

### Source Token Retrieval

Cookie:
```nginx
	map $http_cookie $sts_source_token {
		default "";
		"~*MyCookieName=(?<token>[^;]+)" "$token";
	}
```

Header:
```nginx
	map $http_authorization $sts_source_token {
		default "";
		"~*^Bearer\s+(?<token>[\S]+)$" $token;
	}
```

Query:
```nginx
	if ($args_token != "not found") {
		$sts_source_token = $args_token
	}
```

Post:
```nginx
	# use form-input-nginx-module
	set_form_input $sts_source_token access_token;
```
	
### Source Token Removal

Remove the source token from the incoming request so it is not proxied to the backend.

Cookie:
```nginx
	set $new_cookie $http_cookie;
	if ($http_cookie ~ "(.*)(?:^|;)\s*source_token=[^;]+(.*)") {
		set $new_cookie $1$2;
	}
	proxy_set_header Cookie $new_cookie;
```

Header:
```nginx
	proxy_set_header Authorization "";
```

Query:
```nginx
	if ($args ~ (.*)source_token=[^&]*(.*)) {
		set $args $1$2;
	}
	# cleanup any repeated & introduced 
	if ($args ~ (.*)&&+(.*)) {
		set $args $1&$2;
	}
	# cleanup leading &
	if ($args ~ ^&(.*)) {
		set $args $1;
	}
	# cleanup ending &
	if ($args ~ (.*)&$) {
		set $args $1;
	}
```

### Target Token

Environment: set the target token as a CGI environment variable e.g. for PHP applications:
```nginx
	fastcgi_param STS_TOKEN $sts_target_token
```

Header: pass the target token in a header to the proxied backend:
```nginx
	proxy_set_header Authorization "Bearer $sts_target_token"
```

Cookie: pass the target token to the backend with:
```nginx
	proxy_set_header Cookie STS_COOKIE=$sts_target_token
```

Query: pass the target token in a query parameter to the proxied backend:
```nginx
	set $sep "";
	if ($is_args) {
		set $sep "&";
	}
	set $args $args${sep}token=$sts_target_token;
```

Post: pass the target token in a POST parameter to the proxied backend:
```nginx
	proxy_set_body $request_body&token=$sts_target_token;
```

## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/OpenIDC/ngx_sts_module/wiki](https://github.com/OpenIDC/ngx_sts_module/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you
can contact:  
  [sales@openidc.com](mailto:sales@openidc.com)  


Disclaimer
----------
*This software is open sourced by OpenIDC. For commercial support
you can contact [OpenIDC](https://www.openidc.com) as described above in the [Support](#support)
section.*
