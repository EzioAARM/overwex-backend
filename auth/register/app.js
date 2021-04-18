const AWS = require('aws-sdk')
const crypto = require('crypto')

/**
 * Inicia sesion utilizando cognito
 * @param event Contiene el evento de la funcion (de este se extrae el body)
 * @param context Tiene el contexto de ejecucion de la funcion
 * @param callback Finaliza la ejecucion de la funcion, actua como un return
 */
exports.handler = async (event, context, callback) => {
    try {
        console.log(process.env)
        if (!(JSON.parse(event.body).Username && JSON.parse(event.body).Password && 
            JSON.parse(event.body).Name && JSON.parse(event.body).Email))
            callback(null, {
                statusCode: 400,
                headers: {
                    "Access-Control-Allow-Headers" : "*",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "*"
                },
                body: JSON.stringify({
                    message: (!JSON.parse(event.body).Username) ? "El nombre de usuario es requerido" : 
                        (!JSON.parse(event.body).Password) ? "La contraseña es requerida" :
                        (!JSON.parse(event.body).Name) ? "El nombre es requerido" :
                        (!JSON.parse(event.body).Email) ? "El correo electrónico es requerido" :
                        (!JSON.parse(event.body).OverwexTag) ? "El tag de Overwex es requerido" :
                        "El número de teléfono es requerido"
                })
            })
        const {
            Username, 
            Password, 
            Name, 
            Email
        } = JSON.parse(event.body)
        let Cognito = new AWS.CognitoIdentityServiceProvider();
        const secretHash = crypto.createHmac('sha256', process.env.CognitoSecretClient)
            .update(Username + process.env.CognitoClientId)
            .digest('base64');
        let params = {
            ClientId: process.env.CognitoClientId,
            Password: Password, 
            Username: Username,
            SecretHash: secretHash, 
            UserAttributes: [
                {
                    Name: "name",
                    Value: Name
                },
                {
                    Name: "email",
                    Value: Email
                }
            ]
        }
        const petition = await Cognito.signUp(params).promise();
        callback(null, {
            statusCode: 201,
            headers: {
                "Access-Control-Allow-Headers" : "*",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*"
            }
        })
    }
    catch (e) {
        callback(null, {
            statusCode: e.statusCode,
            headers: {
                "Access-Control-Allow-Headers" : "*",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Methods": "*"
            },
            body: JSON.stringify({
                message: e.message
            })
        })
    }
}
