import { Stack, StackProps, Duration, RemovalPolicy, CfnOutput } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as cognito from 'aws-cdk-lib/aws-cognito';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as pinpoint from 'aws-cdk-lib/aws-pinpoint'

export interface BackendStackProps extends StackProps {
  hasuraClaims: false
  sourceEmail: string /*required*/
  originationNumber: string /*required ONLY when US*/
  pinpointApplicationId: string /*required*/
}

export class BackendStack extends Stack {
  constructor(scope: Construct, id: string, props?: BackendStackProps) {
    super(scope, id, props);

    // check if required variables are provided
    if (!props?.sourceEmail) return

    /**
     * *************************************************************
     *                   PINPONT SMS CHANNEL
     * *************************************************************
    */
    let pinpointSMSChannel
    if (!props?.pinpointApplicationId) {
      pinpointSMSChannel = new pinpoint.CfnSMSChannel(this, 'PinpointCfnSMSChannel', {
        applicationId: 'applicationId'
      });
    }


    /**
     * *************************************************************
     *                   LAMBDA FUNCTIONS
     * *************************************************************
    */
    const lambdaNodeFunctionProps = {
      runtime: lambda.Runtime.NODEJS_14_X,
      timeout: Duration.minutes(5),
    }

    // define auth challenge
    const defineAuthChallenge = new lambda.Function(this, 'DefineAuthChallenge', {
      code: lambda.Code.fromAsset('lambda/define-auth-challenge'),
      handler: "define-auth-challenge.handler",
      ...lambdaNodeFunctionProps
    })

    // create auth challenge
    const _originationNumber = props?.originationNumber ? props?.originationNumber : ""
    const _pinpointApplicationId = pinpointSMSChannel?.applicationId ? pinpointSMSChannel?.applicationId : props.pinpointApplicationId

    const createAuthChallenge = new lambda.Function(this, 'CreateAuthChallenge', {
      code: lambda.Code.fromAsset('lambda/create-auth-challenge/'),
      handler: "create-auth-challenge.handler",
      environment: {
        'ORIGINATIONNUMBER': _originationNumber,
        'PINPOINTAPPLICATIONID': _pinpointApplicationId,
        'SESFROMADDRESS': props.sourceEmail
      },
      ...lambdaNodeFunctionProps
    })

    // Post authentication 
    const postAuthenticationRole = new iam.Role(this, "postAuthenticationRole", {
      assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole")]
    })

    const postAuthentication = new lambda.Function(this, 'PostAuthentication', {
      code: lambda.Code.fromAsset('lambda/post-authentication'),
      handler: "post-authentication.handler",
      role: postAuthenticationRole,
      ...lambdaNodeFunctionProps
    })

    // Pre sign up
    const preSignUp = new lambda.Function(this, 'PreSignUp', {
      code: lambda.Code.fromAsset('lambda/pre-sign-up'),
      handler: "pre-sign-up.handler",
      ...lambdaNodeFunctionProps
    })

    // Verify auth challenge 
    const verifyAuthChallengeResponse = new lambda.Function(this, 'VerifyAuthChallengeResponse', {
      code: lambda.Code.fromAsset('lambda/verify-auth-challenge-response'),
      handler: "verify-auth-challenge-response.handler",
      ...lambdaNodeFunctionProps
    })

    // Hasura claims token pre token generation
    // This lambda will only be created when hasuraClaims is enabled in props
    let hasuraClaimsCallback
    if (props?.hasuraClaims) {
      hasuraClaimsCallback = new lambda.Function(this, 'HasuraClaimsCallback', {
        code: lambda.Code.fromAsset('lambda/hasura-claims-callback/'),
        handler: "hasura-claims-callback.handler",
        ...lambdaNodeFunctionProps
      })
    }


    /**
     * *************************************************************
     *                   AWS COGNITO USERPOOL
     * *************************************************************
    */
    // lambda triggers
    let lambdaTriggers
    if (props?.hasuraClaims) {
      lambdaTriggers = {
        createAuthChallenge: createAuthChallenge,
        defineAuthChallenge: defineAuthChallenge,
        preSignUp: preSignUp,
        verifyAuthChallengeResponse: verifyAuthChallengeResponse,
        postAuthentication: postAuthentication,
        preTokenGeneration: hasuraClaimsCallback
      }
    } else {
      lambdaTriggers = {
        createAuthChallenge: createAuthChallenge,
        defineAuthChallenge: defineAuthChallenge,
        preSignUp: preSignUp,
        verifyAuthChallengeResponse: verifyAuthChallengeResponse,
        postAuthentication: postAuthentication
      }
    }

    // AWS Cognito UserPool
    const passwordLessCognito = new cognito.UserPool(this, 'PasswordlessAuthentication', {
      signInAliases: {
        phone: true,
        email: true,
      },
      standardAttributes: {
        email: {
          required: true,
          mutable: false,
        },
      },
      mfa: cognito.Mfa.OFF,
      selfSignUpEnabled: true,
      signInCaseSensitive: false,
      removalPolicy: RemovalPolicy.DESTROY,
      passwordPolicy: {
        minLength: 8,
        requireLowercase: false,
        requireUppercase: false,
        requireDigits: false,
        requireSymbols: false,
      },
      lambdaTriggers: lambdaTriggers,
    });

    // AWS Cognito client
    const passwordLessClient = passwordLessCognito.addClient('PasswordLessClient', {
      generateSecret: false,
      authFlows: {
        custom: true
      },
    });

    /**
    * *************************************************************
    *                   AWS IAM
    * *************************************************************
   */

    // attach a role that grants function access to AWS Pinpoint and AWS SES
    createAuthChallenge.role?.attachInlinePolicy(new iam.Policy(this, 'CreateAuthChallengeRole', {
      statements: [new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ['ses:SendEmail', "mobiletargeting:SendMessages"],
        resources: ["*"],
      })],
    }));

    const setUserAttributesPolicy = new iam.Policy(this, 'SetUserAttributesPolicy', {
      statements: [new iam.PolicyStatement({
        actions: ['cognito-idp:AdminUpdateUserAttributes'],
        resources: [passwordLessCognito.userPoolArn],
      })],
    })

    setUserAttributesPolicy.attachToRole(postAuthenticationRole)

    // define auth challenge lambda invoke permission
    defineAuthChallenge.addPermission('DefineAuthChallenge Invocation', {
      principal: new iam.ServicePrincipal('cognito-idp.amazonaws.com'),
      sourceArn: passwordLessCognito.userPoolArn,
      action: "lambda:InvokeFunction"
    });

    // create auth challenge lambda invoke permission
    createAuthChallenge.addPermission('CreateAuthChallenge Invocation', {
      principal: new iam.ServicePrincipal('cognito-idp.amazonaws.com'),
      sourceArn: passwordLessCognito.userPoolArn,
      action: "lambda:InvokeFunction"
    });

    // verify auth challenge lambda invoke permission
    verifyAuthChallengeResponse.addPermission('VerifyAuthChallengeResponse Invocation', {
      principal: new iam.ServicePrincipal('cognito-idp.amazonaws.com'),
      sourceArn: passwordLessCognito.userPoolArn,
      action: "lambda:InvokeFunction"
    });

    // pre signup lambda invoke permission
    preSignUp.addPermission('PreSignUp Invocation', {
      principal: new iam.ServicePrincipal('cognito-idp.amazonaws.com'),
      sourceArn: passwordLessCognito.userPoolArn,
      action: "lambda:InvokeFunction"
    });

    // post authentication lambda invoke permission
    postAuthentication.addPermission('PostAuthentication Invocation', {
      principal: new iam.ServicePrincipal('cognito-idp.amazonaws.com'),
      sourceArn: passwordLessCognito.userPoolArn,
      action: "lambda:InvokeFunction"
    });

    // hasura claims callback lambda invoke permission
    if (props?.hasuraClaims) {
      hasuraClaimsCallback?.addPermission('HasuraClaimsCallback Invocation', {
        principal: new iam.ServicePrincipal('cognito-idp.amazonaws.com'),
        sourceArn: passwordLessCognito.userPoolArn,
        action: "lambda:InvokeFunction"
      });
    }

    // On completion output the UserPoolId
    new CfnOutput(this, "UserPoolId", {
      value: passwordLessCognito.userPoolId,
      exportName: "UserPoolId",
      description: "ID of the User Pool"
    });

    // On completion output the UserPoolClientId
    new CfnOutput(this, "UserPoolClientId", {
      value: passwordLessClient.userPoolClientId,
      exportName: "UserPoolClientId",
      description: "ID of the User Pool Client"
    });
  }
}
