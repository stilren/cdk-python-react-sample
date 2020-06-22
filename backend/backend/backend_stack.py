from aws_cdk import (
    core,
    aws_lambda as _lambda,
    aws_apigateway as _apigw,
    aws_apigatewayv2 as _apigw2,
    aws_dynamodb as dynamodb,
    aws_s3 as _s3,
    aws_iam as _iam,
    aws_cognito as _cognito
)


class BackendStack(core.Stack):

    def __init__(self, scope: core.Construct, id: str, **kwargs) -> None:
        super().__init__(scope, id, **kwargs)
        table = dynamodb.Table(self, "Dynamo",
                               partition_key=dynamodb.Attribute(
                                   name="pk", type=dynamodb.AttributeType.STRING),
                               sort_key=dynamodb.Attribute(
                                   name="sk", type=dynamodb.AttributeType.STRING),
                                removal_policy=core.RemovalPolicy.DESTROY
                               )

        http_api = add_cors_http_api(self)

        website_bucket = add_website_bucket(self)

        user_pool, identity_pool, user_pool_client = add_cognito(self)

        authorizer = _apigw2.CfnAuthorizer(self, "MyAuthorizer",
                                           api_id=http_api.http_api_id,
                                           authorizer_type="JWT",
                                           jwt_configuration={
                                               "audience": [user_pool_client.user_pool_client_id], "issuer": f"https://cognito-idp.eu-west-1.amazonaws.com/{user_pool.user_pool_id}"},
                                           identity_source=[
                                               '$request.header.Authorization'],
                                           name="MyAuthorizer",
                                           )

        lambdas = [
            {
                "name": "create",
                "method": _apigw2.HttpMethod.POST,
            },
            {
                "name": "list",
                "method": _apigw2.HttpMethod.GET,
            },
            {
                "name": "read",
                "method": _apigw2.HttpMethod.GET,
            },
            {
                "name": "delete",
                "method": _apigw2.HttpMethod.DELETE,
            }
        ]

        for mylambda in lambdas:
            add_lambda(self, mylambda["name"], table,
                       http_api, mylambda["method"], authorizer)

        core.CfnOutput(self, "APP_CLIENT_ID",
                       value=user_pool_client.user_pool_client_id)
        core.CfnOutput(self, "USER_POOL_ID", value=user_pool.user_pool_id)
        core.CfnOutput(self, "PROVIDER",
                       value=user_pool.user_pool_provider_name)
        core.CfnOutput(self, "GATEWAY_URL", value=http_api.url)
        core.CfnOutput(self, "BUCKET_URL",
                       value=website_bucket.bucket_website_url)
        core.CfnOutput(self, "BUCKET_NAME", value=website_bucket.bucket_name)
        core.CfnOutput(self, "REGION", value=core.Aws.REGION)
        core.CfnOutput(self, "IDENTITY_POOL_ID", value=identity_pool.ref)


def add_lambda(self, name: str, table, apigw, method, authorizer):
    mylambda = _lambda.Function(self, f'{name}-ApiLambda',
                                handler=f'{name}.handler',
                                runtime=_lambda.Runtime.PYTHON_3_7,
                                code=_lambda.Code.asset(
                                    f'backend/lambda'),
                                )
    mylambda.add_environment("TABLE_NAME", table.table_name)
    table.grant_read_write_data(mylambda)
    lambda_integration = _apigw2.LambdaProxyIntegration(
        handler=mylambda)
    routes = apigw.add_routes(
        path=f'/note/{name}',
        methods=[method],
        integration=lambda_integration,
    )
    for route in routes:
        routeCfn = route.node.default_child
        routeCfn.authorizer_id = authorizer.ref
        routeCfn.authorization_type = 'JWT'


def add_cognito(self):
    password_policy = _cognito.PasswordPolicy(
        require_lowercase=False,
        require_digits=False,
        require_symbols=False,
        require_uppercase=False,
    )

    user_pool = _cognito.UserPool(self, 'UserPool',
                                  password_policy=password_policy,
                                  user_pool_name='UserPool',
                                  self_sign_up_enabled=True,
                                  user_verification={
                                        "email_subject": "Verify your email for our awesome app!",
                                      "email_body": "Hello {username}, Thanks for signing up to our awesome app! Your verification code is {####}",
                                      "email_style": _cognito.VerificationEmailStyle.CODE,
                                  },
                                  user_invitation={
                                      "email_subject": "Invite to join our awesome app!",
                                      "email_body": "Hello {username}, you have been invited to join our awesome app! Your temporary password is {####}",
                                  },
                                  sign_in_aliases={
                                      "email": True
                                  },
                                  auto_verify={"email": True},
                                  )

    user_pool_client = user_pool.add_client("AppClient",
                                            auth_flows={
                                                "user_password": True,
                                                "user_srp": True,
                                                "refresh_token": True,
                                                "admin_user_password": True
                                            })

    idp = _cognito.CfnIdentityPool.CognitoIdentityProviderProperty(client_id=user_pool_client.user_pool_client_id,
                                                                   provider_name=user_pool.user_pool_provider_name)
    identity_pool = _cognito.CfnIdentityPool(self, "IdPool",
                                             allow_unauthenticated_identities=False,
                                             cognito_identity_providers=[
                                                   idp]
                                             )

    authenticated_principal = _iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
        "StringEquals": {"cognito-identity.amazonaws.com:aud": identity_pool.ref},
        "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
    }, "sts:AssumeRoleWithWebIdentity")

    unauthenticated_principal = _iam.FederatedPrincipal('cognito-identity.amazonaws.com', {
        "StringEquals": {"cognito-identity.amazonaws.com:aud": identity_pool.ref},
        "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
    }, "sts:AssumeRoleWithWebIdentity")

    authenticated_role = _iam.Role(
        self, "CognitoDefaultAuthenticatedRole", assumed_by=authenticated_principal)

    unauthenticated_role = _iam.Role(
        self, "CognitoDefaultUnAuthenticatedRole", assumed_by=unauthenticated_principal)

    authenticated_policy = _iam.PolicyStatement(
        effect=_iam.Effect.ALLOW,
        actions=[
            "mobileanalytics:PutEvents",
            "cognito-sync:*",
            "cognito-identity:*"
        ],
        resources=["*"]
    )

    unauthenticated_policy = _iam.PolicyStatement(
        effect=_iam.Effect.ALLOW,
        actions=[
            "mobileanalytics:PutEvents",
            "cognito-sync:*",
        ],
        resources=["*"]
    )

    authenticated_role.add_to_policy(authenticated_policy)

    unauthenticated_role.add_to_policy(unauthenticated_policy)

    _cognito.CfnIdentityPoolRoleAttachment(self, "DefaultValidRoleAttachment",
                                           identity_pool_id=identity_pool.ref,
                                           roles={"authenticated": authenticated_role.role_arn, "unauthenticated": unauthenticated_role.role_arn})

    return user_pool, identity_pool, user_pool_client


def add_website_bucket(self):
    website_bucket = _s3.Bucket(self, "WebsiteBucket",
                                website_index_document="index.html",
                                block_public_access=_s3.BlockPublicAccess(restrict_public_buckets=False),
                                removal_policy=core.RemovalPolicy.DESTROY)

    bucket_policy = _iam.PolicyStatement(
        actions=['s3:GetObject'],
        resources=[f'{website_bucket.bucket_arn}/*'],
        principals=[_iam.Anyone()]
    )

    website_bucket.add_to_resource_policy(bucket_policy)

    return website_bucket


def add_cors_http_api(self):
    cors_preflight = _apigw2.CorsPreflightOptions(
        allow_credentials=False,
        allow_headers=['*'],
        allow_methods=[_apigw2.HttpMethod.GET, _apigw2.HttpMethod.HEAD,
                       _apigw2.HttpMethod.OPTIONS, _apigw2.HttpMethod.POST, _apigw2.HttpMethod.PUT, _apigw2.HttpMethod.DELETE],
        allow_origins=['*'],
    )

    http_api = _apigw2.HttpApi(self, "ApiGwId",
                               api_name="HttpGateway",
                               cors_preflight=cors_preflight,
                               )

    return http_api
