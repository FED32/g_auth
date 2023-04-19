import flask
from flask import jsonify
import requests
import google.oauth2.credentials
import google_auth_oauthlib.flow
import googleapiclient.discovery
from google.auth.exceptions import GoogleAuthError, TransportError, RefreshError, OAuthError
from werkzeug.exceptions import BadRequestKeyError
from flasgger import Swagger, swag_from
import config
from config import Configuration
import logger

logger = logger.init_logger()

app = flask.Flask(__name__)
app.config.from_object(Configuration)
# app.config['SWAGGER'] = {"title": "GTCOM-GAdsApi", "uiversion": 3}
app.secret_key = '1234'

# swagger_config = {
#     "headers": [],
#     "specs": [
#         {
#             "endpoint": "apispec_1",
#             "route": "/apispec_1.json()",
#             "rule_filter": lambda rule: True,
#             "model_filter": lambda tag: True,
#         }
#     ],
#     "static_url_path": "/flasgger_static",
#     "swagger_ui": True,
#     "specs_route": "/swagger/",
# }
#
# swagger = Swagger(app, config=swagger_config)


def credentials_to_dict(credentials):
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}


@app.route('/authorize')
# @swag_from("swagger_conf/authorize.yml")
def authorize():
    try:
        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            client_secrets_file=config.client_secrets_file,
            scopes=config.SCOPES
        )

        flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
        # flow.redirect_uri = 'https://oauth2.example.com/code'
        # flow.redirect_uri = flask.url_for("https://ecomru.ru", _external=True)
        # flow.redirect_uri = "https://ecomru.ru"
        # flow.redirect_uri = "https://lk.ecomru.ru"
        # flow.redirect_uri = "http://127.0.0.1"
        # flow.redirect_uri = flask.url_for("lk.ecomru.ru", _external=True)

        # print(flow.redirect_uri)

        authorization_url, state = flow.authorization_url(
            access_type='offline',
            prompt='consent',
            include_granted_scopes='true')

        # print(authorization_url)
        # print(state)

        # Store the state so the callback can verify the auth server response.
        flask.session['state'] = state

        return flask.redirect(authorization_url)

    except (GoogleAuthError, TransportError, RefreshError, OAuthError) as ex:
        logger.error(f"authorize error: {ex}")
        return jsonify({'error': "google auth error"})


@app.route('/oauth2callback')
# @app.route('/')
def oauth2callback():
    try:
        state = flask.session['state']

        flow = google_auth_oauthlib.flow.Flow.from_client_secrets_file(
            client_secrets_file=config.client_secrets_file,
            scopes=config.SCOPES,
            state=state
        )
        flow.redirect_uri = flask.url_for('oauth2callback', _external=True)
        # flow.redirect_uri = "https://lk.ecomru.ru"
        # flow.redirect_uri = "http://127.0.0.1"
        # flow.redirect_uri = "https://ecomru.ru"

        authorization_response = flask.request.url
        # print(authorization_response)
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials

        flask.session['credentials'] = credentials_to_dict(credentials)
        print(flask.session['credentials'])

        logger.info(f"credentials successfully")

        # здесь будет код сохранения токена в базу

        return jsonify(flask.session['credentials'])
        # return flask.redirect("https://lk.ecomru.ru")

    except (GoogleAuthError, TransportError, RefreshError, OAuthError) as ex:
        logger.error(f"oauth2callback error: {ex}")
        return jsonify({'error': "google auth error"})

