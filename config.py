import os


class Configuration(object):
    DEBUG = False


client_secrets_file = 'client_secret_660722585949-478ao09befcevaosv1ot311so9dt5575.apps.googleusercontent.com.json'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

SCOPES = ["https://www.googleapis.com/auth/userinfo.email",
          "https://www.googleapis.com/auth/userinfo.profile",
          "https://www.googleapis.com/auth/adwords"
          ]
# SCOPES = ["https://www.googleapis.com/auth/adwords"]

redirect_uri = "https://apps0.ecomru.ru:4431/oauth2callback"
# redirect_uri = "http://127.0.0.1:5000/oauth2callback"


PG_HOST = os.environ.get('ECOMRU_PG_HOST', None)
PG_PORT = os.environ.get('ECOMRU_PG_PORT', None)
PG_SSL_MODE = os.environ.get('ECOMRU_PG_SSL_MODE', None)
PG_DB_NAME = os.environ.get('ECOMRU_PG_DB_NAME', None)
PG_USER = os.environ.get('ECOMRU_PG_USER', None)
PG_PASSWORD = os.environ.get('ECOMRU_PG_PASSWORD', None)
PG_target_session_attrs = 'read-write'

CH_HOST = os.environ.get('ECOMRU_CH_HOST', None)
CH_DB_NAME = os.environ.get('ECOMRU_CH_DB_NAME', None)
CH_USER = os.environ.get('ECOMRU_CH_USER', None)
CH_PASSWORD = os.environ.get('ECOMRU_CH_PASSWORD', None)
CH_PORT = os.environ.get('ECOMRU_CH_PORT', None)


PG_DB_PARAMS = f"postgresql://{PG_USER}:{PG_PASSWORD}@{PG_HOST}:{PG_PORT}/{PG_DB_NAME}"

FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', None)


CLIENT_ID = '660722585949-478ao09befcevaosv1ot311so9dt5575.apps.googleusercontent.com'
CLIENT_SECRET = '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'
# LOGIN_CUSTOMER_ID = '8294188123'
DEVELOPER_TOKEN = 'e02pIe5eebUjGPnk8BiG3Q'

