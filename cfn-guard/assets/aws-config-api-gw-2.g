let config := * # for each element in array
let gateway := %config.configuration

rule check_is_api_gateway_resource {
    %config.version == "1.3"
    %config.resourceType == "AWS::ApiGateway::Stage"
}

rule api_gateway_v2_throttle_limits {
    check_is_api_gateway_resource
    AWS::ApiGateway::Stage {
        %gateway.throttlingBurstLimit >= %PARAMETERS.throttlingBurstLimitMin
        %gateway.throttlingBurstLimit <= %PARAMETERS.throttlingBurstLimitMax

        %gateway.throttlingRateLimit >= %PARAMETERS.throttlingRateLimitMin
        %gateway.throttlingRateLimit <= %PARAMETERS.throttlingRateLimitMax
    }



rule api_gateway_v2_ssl_enabled {
    check_is_api_gateway_resource
    AWS::ApiGateway::Stage {
        %gateway.clientCertificateId != null

        %gateway.clientCertificateId IN %PARAMETERS.CertificateIDs OR
        %PARAMETERS.CertificateIDs == null
    }
}

rule api_gateway_v2_xray_enabled {
    check_is_api_gateway_resource
    AWS::ApiGateway::Stage {
        %gateway.tracingEnabled == true
    }
}

rule api_gateway_v2_authorized_method_cached {
    check_is_api_gateway_resource
    AWS::ApiGateway::Stage {
        %gateway.cacheClusterEnabled == null
    } OR
    AWS::ApiGateway::Stage {
        %gateway.cacheClusterEnabled != null
        let ms := %gateway.methodSettings
        %ms.*.cachingEnabled == true
        %ms.
    }

}
