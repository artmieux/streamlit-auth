import streamlit as st
import auth

auth = auth.Authenticator(
  {
    "creds_file": "credentials.pickle",
    "cookie_name": "sbldashauth",
    "cookie_expiry_days": 30,
    "token_key": "secret",
    "admin_roles": ["su", "admin"],
    "assignable_roles": ["user", "admin"],
    "default_users": {
      "admin": {
        "name": "admin",
        "role": "su",
        "password": "admin"
      }
    }
  }
)

auth.login_form()

with st.sidebar:
  auth.account_panel()
  auth.admin_panel()
