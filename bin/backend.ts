#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { BackendStack } from '../lib/backend-stack';

const prodRegion = 'us-east-2' /*Your recources will be deployed in this region*/
const hasuraClaims = false /*required incase using AWS Cognito with Hasura*/

// With AWS Pinpoint in US you have to provide origination number
// Update the createAuthChallenge lambda with origination number

const pinpointApplicationId = "3ccaf76f60d5438b8e98a1698b6c3d88" /*required*/
const originationNumber = "" /*required only when sending SMS in US*/
const sourceEmail = "crudavid36@gmail.com" /*required*/

const app = new cdk.App();

new BackendStack(app, 'BackendStack', {
  pinpointApplicationId: pinpointApplicationId,
  hasuraClaims: hasuraClaims,
  sourceEmail: sourceEmail,
  originationNumber: originationNumber,
  env: {
    region: prodRegion
  }
});
