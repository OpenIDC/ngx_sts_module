# ngx_sts_module

A security token exchange module for the NGINX web server which allows for exchanging arbitrary security tokens by calling into a remote Security Token Service (STS).
For an overview and rationale see the Apache version of this module at https://github.com/zmartzone/mod_sts/blob/master/README.md.

## Quickstart

WS-Trust STS with HTTP Basic authentication and setting the target token in a cookie.

```
       location /sts/wstrust {
            STSType wstrust;
            STSSSLValidateServer Off;
            STSWSTrustEndpoint https://pingfed:9031/pf/sts.wst;
            STSWSTrustEndpointAuth basic username=wstrust&password=2Federate;
            STSWSTrustAppliesTo urn:pingfed;
            STSWSTrustValueType urn:pingidentity.com:oauth2:grant_type:validate_bearer;
            STSWSTrustTokenType urn:bogus:token;

            STSVariables $source_token $wst_target_token;
            
            proxy_set_header Cookie STS_COOKIE=$wst_target_token;
            proxy_pass http://echo:8080/headers$is_args$args;
        }
```

OAuth 2.0 Resource Owner Password Credentials based Token Exchange with `client_secret_basic` authentication.

```    
        location /sts/ropc {
            STSType ropc;
            STSSSLValidateServer Off;
            STSROPCEndpoint https://pingfed:9031/as/token.oauth2;
            STSROPCEndpointAuth client_secret_basic client_id=sts0&client_secret=2Federate;
            STSROPCUsername dummy;
            
            STSVariables $source_token $ropc_target_token;
            
            proxy_set_header Cookie STS_COOKIE=$ropc_target_token;
            proxy_pass http://echo:8080/headers$is_args$args;            
        }
```

OAuth 2.0 Token Exchange with `client_secret_basic` authentication.

```
        location /sts/otx {
            STSType otx;
            STSSSLValidateServer Off;
            STSOTXEndpoint https://keycloak:8443/auth/realms/master/protocol/openid-connect/token;
            STSOTXEndpointAuth client_secret_basic client_id=otxclient&client_secret=2Federate;

            STSVariables $source_token $otx_target_token;
            
            proxy_set_header Cookie STS_COOKIE=$otx_target_token;
            proxy_pass http://echo:8080/headers$is_args$args;            
        }        
```

## Configuration 

### Source Token Retrieval

Cookie:
```
	map $http_cookie $sts_source_token {
		default "";
		"~*MyCookieName=(?<token>[^;]+)" "$token";
	}
```

Header:
```
	map $http_authorization $sts_source_token {
		default "";
		"~Bearer (?<token>.+)$" "$token";
	}
```

Query:
```
	if ($args_token != "not found") {
		$sts_source_token = $args_token
	}
```

Post:
```
	# use form-input-nginx-module
	set_form_input $sts_source_token access_token;
```
	
### Source Token Removal

Remove the source token from the incoming request so it is not proxied to the backend.

Cookie:
```
	set $new_cookie $http_cookie;
	if ($http_cookie ~ "(.*)(?:^|;)\s*source_token=[^;]+(.*)") {
		set $new_cookie $1$2;
	}
	proxy_set_header Cookie $new_cookie;
```

Header:
```
	proxy_set_header Authorization "";
```

Query:
```
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
```
	fastcgi_param STS_TOKEN $sts_target_token
```

Header: pass the target token in a header to the proxied backend:
```
	proxy_set_header Authorization "Bearer $sts_target_token"
```

Cookie: pass the target token to the backend with:
```
	proxy_set_header Cookie STS_COOKIE=$sts_target_token
```

Query: pass the target token in a query parameter to the proxied backend:
```
	set $sep "";
	if ($is_args) {
		set $sep "&";
	}
	set $args $args${sep}token=$sts_target_token;
```

Post: pass the target token in a POST parameter to the proxied backend:
```
	proxy_set_body $request_body&token=$sts_target_token;
```

## Support

#### Community Support
For generic questions, see the Wiki pages with Frequently Asked Questions at:  
  [https://github.com/zmartzone/ngx_sts_module/wiki](https://github.com/zmartzone/ngx_sts_module/wiki)  
Any questions/issues should go to issues tracker.

#### Commercial Services
For commercial Support contracts, Professional Services, Training and use-case specific support you can contact:  
  [sales@zmartzone.eu](mailto:sales@zmartzone.eu)  


Disclaimer
----------
*This software is open sourced by ZmartZone IAM. For commercial support
you can contact [ZmartZone IAM](https://www.zmartzone.eu) as described above in the [Support](#support) section.*
