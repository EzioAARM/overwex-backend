const AWS = require('aws-sdk')
const crypto = require('crypto')

exports.handler = async (event, context, callback) => {
    try {
        if (!(JSON.parse(event.body).Username && JSON.parse(event.body).Password))
            callback(null, {
                statusCode: 400,
                headers: {
                    "Access-Control-Allow-Headers" : "*",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "*"
                },
                body: JSON.stringify({
                    message: (!JSON.parse(event.body).Username) ? "El nombre de usuario es requerido" : 
                        "La contraseña es requerida"
                })
            })
        const {
            Username,
            Password
        } = JSON.parse(event.body)
        const secretHash = crypto.createHmac('sha256', process.env.CognitoSecretClient)
                .update(Username + process.env.CognitoClientId)
                .digest().toString('base64');
        let params = {
            AuthFlow: 'ADMIN_NO_SRP_AUTH',
            ClientId: process.env.CognitoClientId,
            UserPoolId: process.env.CognitoPoolId,
            AuthParameters: {
                USERNAME: Username,
                PASSWORD: Password,
                SECRET_HASH: secretHash
            }
        }
        let Cognito = new AWS.CognitoIdentityServiceProvider();
        const loginResponse = await Cognito.adminInitiateAuth(params).promise()
        callback(null, {
            statusCode: 200,
            headers: {
                "Access-Control-Allow-Headers" : "*",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*"
            },
            body: JSON.stringify({
                token: loginResponse.AuthenticationResult.AccessToken,
                refreshToken: loginResponse.AuthenticationResult.RefreshToken,
                idToken: loginResponse.AuthenticationResult.IdToken
            })
        })
    } catch (e) {
        callback(null, {
            body: JSON.stringify({
                message: e.message
            }),
            headers: {
                "Access-Control-Allow-Headers" : "*",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*"
            },
            statusCode: e.statusCode
        })
    }
}
