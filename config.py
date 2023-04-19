import os


class Configuration(object):
    DEBUG = False


client_secrets_file = 'client_secret_660722585949-478ao09befcevaosv1ot311so9dt5575.apps.googleusercontent.com.json'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

SCOPES = ["https://www.googleapis.com/auth/adwords"]


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

