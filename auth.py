import streamlit as st
import pickle
import bcrypt
import extra_streamlit_components as stx
import datetime as dt
import jwt

def initialize_session_state(keys: list[str]) -> None :
  for key in keys:
    if key not in st.session_state:
      st.session_state[key] = None

class Authenticator:
  @staticmethod
  def read_credentials(creds_file:str) -> dict:
    with open(creds_file, "rb") as file:
      return pickle.load(file)

  @staticmethod
  def save_credentials(creds_file:str, creds:dict) -> None:
    with open(creds_file, "wb") as file:
      pickle.dump(creds, file)

  @staticmethod
  def logged_in() -> bool:
    return st.session_state["authentication_status"] == "logged_in"

  @staticmethod
  def logged_out() -> bool:
    return st.session_state["authentication_status"] == "logged_out"  

  @staticmethod
  def hash_pwd(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

  def __init__(self, config:dict) -> None:
    """
    """
    self.creds_file = config["creds_file"]
    self.cookie_name = config["cookie_name"]
    self.cookie_expiry_days = config["cookie_expiry_days"]
    self.token_key = config["token_key"]
    self.admin_roles = config["admin_roles"]
    self.assignable_roles = config["assignable_roles"]

    self.expiry_date = dt.datetime.utcnow() + dt.timedelta(days=self.cookie_expiry_days)
    self.cookie_manager = stx.CookieManager()

    initialize_session_state(['email', 'name', 'role', 'authentication_status', 'token'])

    try:
      self.credentials = Authenticator.read_credentials(self.creds_file)
    except:
      self.credentials = {}
      new_users = config["default_users"]
      for email in new_users.keys():
        self.credentials[email] = {
          "name": new_users[email]["name"],
          "role": new_users[email]["role"],
          "password": Authenticator.hash_pwd(new_users[email]["password"])
        }
      print(self.credentials)
      Authenticator.save_credentials(self.creds_file, self.credentials)

  def check_password(self, email:str, password:str) -> bool:
    if email in list(self.credentials):
      return bcrypt.checkpw(password.encode('utf-8'), self.credentials[email]["password"])
    else:
      return False
  
  def decode_token(self, token):
    try:
      return jwt.decode(token, key=self.token_key, algorithms=['HS256'])
    except:
      return False

  def verify_token(self):
    cookie = self.cookie_manager.get(cookie=self.cookie_name)
    if cookie is not None:
      token = self.decode_token(cookie)
      if token is not False:
        if not Authenticator.logged_out():
          if token["exp_date"] > dt.datetime.utcnow().timestamp():
            if 'email' and 'name' and 'role' in token:
              st.session_state["email"] = token["email"]
              st.session_state["name"] = token["name"]
              st.session_state["role"] = token["role"]
              st.session_state["authentication_status"] = "logged_in"

  def encode_token(self):
    return jwt.encode(
      {
        'email': st.session_state['email'],
        'name': st.session_state['name'],
        'role': st.session_state['role'],
        'exp_date': self.expiry_date.timestamp()
      },
      self.token_key,
      algorithm='HS256'
    )

  def verify_credentials(self, email:str, password:str) -> None:
    if email in self.credentials:
      if self.check_password(email, password):
        st.session_state["email"] = email
        st.session_state["name"] = self.credentials[email]["name"]
        st.session_state["role"] = self.credentials[email]["role"]
        st.session_state["authentication_status"] = "logged_in"
        self.cookie_manager.set(self.cookie_name, self.encode_token(), expires_at=self.expiry_date)

  def login_form(self) -> None:
    self.verify_token()
    if not Authenticator.logged_in():
      login_form = st.form('Login')
      login_form.subheader('Login')
      email = login_form.text_input('Email').lower()
      password = login_form.text_input('Password', type='password')
      if login_form.form_submit_button('Login'):
        self.verify_credentials(email, password)
    
  def logout_button(self) -> None:
    if Authenticator.logged_in():
      if st.button('Logout', 'logout-button'):
        self.cookie_manager.delete(self.cookie_name)
        st.session_state['email'] = None
        st.session_state['name'] = None
        st.session_state['role'] = None
        st.session_state['authentication_status'] = "logged_out"
        # st.experimental_rerun()
  
  def account_panel(self):
    if self.logged_in():
      st.write(f"Logged in as *{st.session_state['name']}*")
      self.logout_button()
      if st.session_state["name"] != "admin":
        with st.expander("Update name"):
          self.update_name_form()
      with st.expander("Reset password"):
        self.reset_password_form()    

  def update_name_form(self):
    update_name_form = st.form('Update user name')
    self.name = update_name_form.text_input('New name')
    if update_name_form.form_submit_button('Update'):
      if len(self.name) > 1:
        if self.name != self.credentials[st.session_state["email"]]["name"]:
            st.session_state["name"] = self.name
            self.credentials[st.session_state["email"]]["name"] = self.name
            self.save_credentials(self.creds_file, self.credentials)
            self.cookie_manager.set(self.cookie_name, self.encode_token(), expires_at=self.expiry_date)
            st.info("Name changed")
        else:
          st.error('New and current values are the same')
      else:
        st.error('User name must be 2 characters minimum.')

  def reset_password_form(self):
    reset_password_form = st.form('Reset password')
    old_password = reset_password_form.text_input('Current password', type='password')
    new_password = reset_password_form.text_input('New password', type='password')
    new_password_repeat = reset_password_form.text_input('Repeat password', type='password')
    if reset_password_form.form_submit_button('Submit'):
      email = st.session_state["email"]
      if self.check_password(email, old_password):
        if len(new_password) > 4:
          if new_password == new_password_repeat:
            self.credentials[email]["password"] = Authenticator.hash_pwd(new_password)
            self.save_credentials(self.creds_file, self.credentials)
            st.success("Password changed")
          else:
            st.error("Password confirmation does not match.")
        else:
          st.error('New password is invalid')
      else:
        st.error("Current password is not correct.")
  
  def isadmin(self) -> bool:
    return st.session_state["role"] in self.admin_roles
  
  def admin_panel(self):
    if self.logged_in() and self.isadmin():
      st.write(f"User administration")
      with st.expander("Add user"):
          self.add_user_form()
      with st.expander("Remove user"):
          self.delete_user_form()
  
  def adduser(self, new_user_email, new_user_name, new_user_role, new_user_password):
    self.credentials[new_user_email] = {
      "name": new_user_name,
      "role": new_user_role,
      "password": Authenticator.hash_pwd(new_user_password)
    }
    self.save_credentials(self.creds_file, self.credentials)

  def add_user_form(self):
    if self.isadmin():
      add_user_form = st.form('Add user')
      new_user_email = add_user_form.text_input('New user email')
      new_user_name = add_user_form.text_input('New user name')
      new_user_role = add_user_form.selectbox('New user role', self.assignable_roles)
      new_user_password = add_user_form.text_input('New user password', type='password')
      new_user_password_repeat = add_user_form.text_input('Repeat password', type='password')
      if add_user_form.form_submit_button('Add user'):
        if new_user_email not in self.credentials.keys():
          if True: # to do: validate email
            if len(new_user_name) > 1:
              if len(new_user_password) > 4:
                if new_user_password == new_user_password_repeat:
                  self.adduser(new_user_email, new_user_name, new_user_role, new_user_password)
                  st.success("New user added.")
                else:
                  st.error("Password confirmation does not match.")
              else:
                st.error("password is invalid")
            else:
              st.error("User name must be al least 2 characters")
          else:
            st.error("Email formmat is incorrect")
        else:
          st.error("A user with that email already exists.")

  def current_user(self):
    return st.session_state["email"]
  
  def other_users(self):
    users = list(self.credentials.keys())
    users.remove('admin')
    if self.current_user() in users:
      users.remove(self.current_user())
    return users
  
  def delete_user_form(self):
    if self.isadmin():
      remove_user_form = st.form('Remove user')
      user = remove_user_form.selectbox('Select user', self.other_users())
      confirm = remove_user_form.checkbox('Confirm')
      if remove_user_form.form_submit_button('Remove User'):
        if confirm:
          del self.credentials[user]
          self.save_credentials(self.creds_file, self.credentials)
          st.success('User removed.')
