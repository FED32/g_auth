import flask
from flask import jsonify, request
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from google.auth.exceptions import GoogleAuthError, TransportError, RefreshError, OAuthError
# from werkzeug.exceptions import BadRequestKeyError
import jwt
# from base64 import b64decode
import config
from config import Configuration
from ecom_g_ads import GAdsEcomru
import logger


logger = logger.init_logger()

app = flask.Flask(__name__)
app.config.from_object(Configuration)
app.secret_key = config.FLASK_SECRET_KEY


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes,
            'id_token': credentials.id_token
            }


# def decode_user(token: str):
#     """
#     :param token: jwt token
#     :return:
#     """
#     decoded_data = jwt.decode(jwt=token,
#                               key='secret',
#                               algorithms=["RS256"])
#     print(decoded_data)


@app.route('/authorize')
# @swag_from("swagger_conf/authorize.yml")
def authorize():
    try:
        client_id = request.args.get('client_id')
        # flask.session['client_id'] = client_id

        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            client_secrets_file=config.client_secrets_file,
            scopes=config.SCOPES
        )

        # flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
        flow.redirect_uri = config.redirect_uri

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            state=client_id,
            include_granted_scopes='false')

        # Store the state so the callback can verify the auth server response.
        flask.session['state'] = state
        # print(state)

        return flask.redirect(authorization_url)

    except (GoogleAuthError, TransportError, RefreshError, OAuthError) as ex:
        logger.error(f"authorize error: {ex}")
        return jsonify({'error': "google auth error"})


@app.route('/oauth2callback')
# @app.route('/')
def oauth2callback():
    try:
        state = flask.session['state']

        # client_id = flask.session['client_id']
        # client_id = state
        client_id = request.args.get('state')

        if request.args.get('error') is not None:

            # return flask.redirect("https://lk.ecomru.ru")
            return jsonify({'client_id': client_id, 'error': request.args.get('error')})

        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            client_secrets_file=config.client_secrets_file,
            scopes=config.SCOPES,
            state=state
        )
        # flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
        flow.redirect_uri = config.redirect_uri

        authorization_response = flask.request.url
        # print(authorization_response)
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials

        flask.session['credentials'] = credentials_to_dict(credentials)
        logger.info(f"credentials successfully")

        # print(flask.session['credentials'])
        print(credentials.to_json())

        gads = GAdsEcomru(client_id=config.CLIENT_ID,
                          client_secret=config.CLIENT_SECRET,
                          developer_token=config.DEVELOPER_TOKEN,
                          refresh_token=flask.session['credentials']['refresh_token']
                          )

        logins = gads.get_accounts()

        idt = flask.session['credentials']["id_token"]
        user_info = jwt.decode(idt, options={"verify_signature": False})

        result = {
            'client_id': client_id,
            'credentials': flask.session['credentials'],
            'logins': logins,
            'user_info': user_info
        }

        # здесь будет код сохранения учетных данных аккаунта в базу

        return jsonify(result)
        # return flask.redirect("https://lk.ecomru.ru")

    except (GoogleAuthError, TransportError, RefreshError, OAuthError) as ex:
        logger.error(f"oauth2callback error: {ex}")
        return jsonify({'error': "google auth error"})

    except BaseException as ex:
        logger.error(f'oauth2callback error: {ex}')
        return flask.Response(None, 400)


