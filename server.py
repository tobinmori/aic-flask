"""Python Flask WebApp integration example

USAGE: python server-oidc.py {ENV file}

e.g: python server-oidc.py .env.pbstest
"""
import sys
import os
from os import access, environ as env
import json
import constants
from functools import wraps
import requests

from werkzeug.exceptions import HTTPException
from dotenv import load_dotenv, find_dotenv
from flask import Flask, jsonify, redirect, render_template, session, url_for
from authlib.integrations.flask_client import OAuth
from six.moves.urllib.parse import urlencode


# create flask app
app = Flask(__name__, static_url_path='/public', static_folder='./public')
app.secret_key = constants.SECRET_KEY
app.debug = True

# setup err handling
@app.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(message=str(ex))
    response.status_code = (ex.code if isinstance(ex, HTTPException) else 500)
    return response

# open env file
try:
    ENV_FILE = find_dotenv(sys.argv[1])
    app.logger.info(f'Loaded ENV: {ENV_FILE}')
except IndexError:
    app.logger.info('Please specify an .env file.')
    sys.exit()

if ENV_FILE:
    load_dotenv(ENV_FILE) # load env vars into 'env'
    app.logger.info('***LOADED ENV VARS')
    app.logger.info(env)

# globals
AIC_CALLBACK_URL = env.get(constants.AIC_CALLBACK_URL)
AIC_CLIENT_ID = env.get(constants.AIC_CLIENT_ID)
AIC_CLIENT_SECRET = env.get(constants.AIC_CLIENT_SECRET, default=None)
AIC_CUSTOMER_ID = env.get(constants.AIC_CUSTOMER_ID)
AIC_DOMAIN = env.get(constants.AIC_DOMAIN)
AIC_BASE_URL = f"https://{AIC_DOMAIN}/{AIC_CUSTOMER_ID}"
AIC_AUDIENCE = env.get(constants.AIC_AUDIENCE)
AIC_OPENID_CONF = 'https://login.publicmediasignin.org/f29e2df8-7cf0-4741-939b-dc9e9555f527/login/.well-known/openid-configuration'
AIC_SCOPE = 'openid profile email address phone'
PROFILE_SVC_BASE_URL = 'https://profile.services.pbs.org/v2'
PROFILE_SVC_APP_ID = 'pbsaccount' # APPID must be present in profile svcs django admin
VPPA_OPTS = {
            'return_uri':'http://localhost:3000/redirect_uri',
            'handle_ux': 'true',
            'activation': 'true'
}

# register aic as OAuth app. . .
# allow for dynamically registering app, based on selected .env
oauth = OAuth(app)
oauth_reg_kwargs = {  
                'client_id':AIC_CLIENT_ID,
                'api_base_url':AIC_BASE_URL,
                'access_token_url':AIC_BASE_URL + '/login/token',
                'authorize_url':AIC_BASE_URL + '/login/authorize',
                'server_metadata_url':AIC_OPENID_CONF,
                'client_kwargs':{
                    'scope': AIC_SCOPE,
                },
                'authorize_params':{'acr_values' : 'urn:akamai-ic:nist:800-63-3:aal:1'} 
    }
# load a CONFIDENTIAL CLIENT
if AIC_CLIENT_SECRET:
    app.logger.info('Loading CONFIDENTIAL client')
    mods = {  

                'client_secret':AIC_CLIENT_SECRET,
                'client_kwargs': {
                    'scope': AIC_SCOPE,
                },
    }
# or, load a PUBLIC (PKCE) CLIENT
else:
    app.logger.info('Loading PUBLIC client')
    mods = {  

                'client_kwargs': {
                    'scope': AIC_SCOPE,
                    'code_challenge_method': 'S256'
                },
            }

oauth_reg_kwargs.update(mods)
aic = oauth.register('aic', **oauth_reg_kwargs)

# define auth wrapper
def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if constants.PROFILE_KEY not in session:
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated

## convenience methods
def get_login_resolve(access_token):
    """
    POST to Profile Svc's Login Resolve endpoint

    This is an overloaded endpoint in that it does several things:
    - syncs new users to Profile Svc (creates mapping of PID to IDP id)
    - creates a Profile in Profile SVc (if it doesn't exist)
    - inspects Profile and provides VPPA redirect flow if requested

    Other things to know:
    - does NOT use basic auth
    - uses access token for auth
    - Application-ID MUST be registered in Profile Svc otherwise 403
    - returns show_vppa_screen & vppa_redirect
    - code reference: https://projects.pbs.org/bitbucket/projects/CS/repos/profile-service/browse/profile_service/otp/views/v2/login_resolve.py
    - doc reference: https://projects.pbs.org/confluence/display/RTFDPBSOR/1.2.14.+Login+Resolver
    """
    login_resolve_headers =     {   
                                'Authorization':access_token,
                                'Application-Id':PROFILE_SVC_APP_ID
                                }
    vppa_opts = VPPA_OPTS
    res=requests.post(PROFILE_SVC_BASE_URL + '/login_resolve/', headers=login_resolve_headers, data=vppa_opts)
    app.logger.info(f"LOGIN RESOLVE HEADERS: {login_resolve_headers}")
    app.logger.info(f"VPPA OPTS: {vppa_opts}")
    app.logger.info(f"VPPA OPTS: res {res}")
    return res.json()

def get_pbs_profile(access_token):
    '''
    GET user profile using v2 endpoint

    - doc reference: https://projects.pbs.org/confluence/display/RTFDPBSOR/1.2.15.+User
    '''
    app.logger.info(f"GET PBS PROFILE")
    headers =  {   
                    'Authorization':access_token,
                    'Application-Id':PROFILE_SVC_APP_ID
                }
    app.logger.info(f"GET PBS PROFILE:access token: {access_token}")
    res=requests.get(PROFILE_SVC_BASE_URL + '/user/profile/', headers=headers,)
    app.logger.info(res)
    app.logger.info(f"PBS PROFILE: {res.json()}")
    return res.json()

##
## define routes
##
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login')
def login():
    '''Redirect user to SSO login page'''
    return aic.authorize_redirect(redirect_uri=AIC_CALLBACK_URL, audience=AIC_AUDIENCE)

@app.route('/redirect_uri')
def callback_handling():
    '''After login, get all the user's info and redirect to dashboard templ'''
    debug_info = {}
    ## GET Token Response ( a lot more than just a token )
    ## includes access_token, refresh_token, scope, id_token
    access_token=aic.authorize_access_token()
    
    ## GET access token
    app.logger.info(f"ACCESS_TOKEN: {access_token}")
    debug_info.update({'DEBUG:AIC:access_token':access_token})

    ## V1: One way to GET user info is to use the OAuth2 endpoint
    userinfo_endpoint = f"{AIC_CUSTOMER_ID}/profiles/oidc/userinfo"
    resp = aic.get(userinfo_endpoint)
    userinfo = resp.json()
    app.logger.info(f"USERINFO ENDPOINT: {userinfo}")
    debug_info.update({'DEBUG:AIC:userinfo_endpoint':userinfo})

    ## V2: The RIGHT WAY is to parse the id_token to get the same userinfo and more
    userinfo = access_token['userinfo']
    app.logger.info(f"USERINFO from PARSED ID TOKEN: {userinfo}")
    debug_info.update({'DEBUG:AIC:parsed_id_token':userinfo})

    # For INSTRUCTIONAL purposes. . .get PBS stuff: (1) profile and (2) login_resolve info
    pbs_profile = get_pbs_profile(access_token['access_token'])
    app.logger.info(f"PBS PROFILE: {pbs_profile}")
    debug_info.update({'DEBUG:PBS:profile':pbs_profile})

    vppa_resp = get_login_resolve(access_token['access_token'])
    app.logger.info(f"PBS VPPA: {vppa_resp}")
    debug_info.update({'DEBUG:PBS:login_resolve':vppa_resp})
    
    session[constants.JWT_PAYLOAD] = debug_info
    session[constants.PROFILE_KEY] = {
        'user_id': userinfo['sub'],  # USER's AIC UID
    }
    return redirect('/dashboard')

@app.route('/dashboard')
@requires_auth
def dashboard():
    return render_template('dashboard.html',
                           userinfo=session[constants.PROFILE_KEY],
                           userinfo_pretty=json.dumps(session[constants.JWT_PAYLOAD], indent=4))

@app.route('/logout')
def logout():
    '''Logout functionality - clear local cookies and redirect to AIC logout'''
    session.clear() # clear cookies
    params = {
                #'redirect_uri': url_for('home', _external=True),
                'client_id': AIC_CLIENT_ID
              }
    app.logger.info(f"LOGOUT URL: {aic.api_base_url + '/auth-ui/logout?' + urlencode(params)}")
    return redirect(aic.api_base_url + '/auth-ui/logout?' + urlencode(params))

@app.route('/exchange_token')
def exchange_token():
    '''How to use a refresh token to get a new access token'''
    jwt = session[constants.JWT_PAYLOAD]
    refresh_token = jwt['DEBUG:AIC:access_token']['refresh_token']
    app.logger.info(f"REFRESH TOKEN {refresh_token}")
    params = {
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token,
                'client_id': AIC_CLIENT_ID
              }
    
    res=requests.post(AIC_BASE_URL + '/login/token', data=params, )
    app.logger.info(f"REFRESHED THE TOKEN {res.json()}")

    return render_template('dashboard.html',
                           userinfo=res.json(),
                           userinfo_pretty=json.dumps(res.json(), indent=4))

@app.route('/userinfo')
def userinfo_token():
    '''How to get userinfo'''
    jwt = session[constants.JWT_PAYLOAD]
    access_token = jwt['DEBUG:AIC:access_token']['access_token']
    userinfo_endpoint = f"{AIC_BASE_URL}/profiles/oidc/userinfo"
    header = { "Authorization": f"Bearer {access_token}", }
    res = requests.get(userinfo_endpoint, headers=header)
    userinfo = res.json()
    return render_template('dashboard.html',
                           userinfo=userinfo,
                           userinfo_pretty=json.dumps(userinfo, indent=4))


# app runner
if __name__ == "__main__":
    app.run(host='0.0.0.0', port=env.get('PORT', 3000))