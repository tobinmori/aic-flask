# AIC-FLASK

## Purpose

 This is a an example RP implementation of Akamai Identiy Cloud (AIC) using Flask and Authlib. This is meant for demo/educational purposes only.

## Installation #1 (docker way)

1. copy .env.example to .env
2. update client_secret (or anything else in the .env file)
3. docker build -t aic-flask:latest .
4. docker run -d -p 3000:3000 aic-flask

## Installation Method #2

1. python -m venv ve
2. source ./ve/bin/activate
3. pip install -r requirements.txt
4. copy .env.example to .env
5. update client_secret (or anything else in the .env file)
6. python server.py .env.{WHATEVER}

## AIC setup

Make sure:
- you're using a valid login_client in AIC.
- you have http://localhost:3000/redirect_uri (or whatever your redirect url is) set as a valid redirect URI in the AIC client you're using. 

