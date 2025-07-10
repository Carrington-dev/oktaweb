Here’s a sample `README.md` for setting up **Django authentication with Okta** using OAuth 2.0 / OIDC (OpenID Connect), including JWT support:

---

# 🔐 Django Authentication with Okta

This project demonstrates how to implement authentication in a Django application using **Okta** via OAuth 2.0 / OpenID Connect (OIDC), and how to issue and verify **JWTs** for secure communication between frontend and backend.

---

## 🚀 Features

* Okta OAuth 2.0 / OIDC integration
* Login & Logout via Okta
* JWT issuance and verification
* Protected endpoints with token-based access
* CSRF-safe architecture
* Optional: REST API support with Django REST Framework

---

## 🛠 Prerequisites

* Python 3.8+
* Django 4.0+
* Okta Developer Account
* [Django REST Framework](https://www.django-rest-framework.org/) (optional)
* `requests`, `python-jose`, `djangorestframework`, `python-dotenv`

---

## 🔧 Setup Instructions

### 1. Clone the repo

```bash
git clone https://github.com/your-org/django-okta-auth.git
cd django-okta-auth
```

### 2. Install dependencies

```bash
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 3. Configure `.env`

Create a `.env` file with the following values from your Okta app:

```env
OKTA_CLIENT_ID=your-client-id
OKTA_CLIENT_SECRET=your-client-secret
OKTA_ISSUER=https://your-okta-domain.okta.com/oauth2/default
OKTA_REDIRECT_URI=http://localhost:8000/auth/callback/
SECRET_KEY=your-django-secret-key
```

### 4. Django settings (`settings.py`)

Add the following to your `INSTALLED_APPS`:

```python
INSTALLED_APPS = [
    ...
    'rest_framework',
    'your_auth_app',
]
```

Add the authentication middleware and rest settings if needed:

```python
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',
]

REST_FRAMEWORK = {
    'DEFAULT_AUTHENTICATION_CLASSES': (
        'rest_framework.authentication.SessionAuthentication',
        'rest_framework.authentication.BasicAuthentication',
    )
}
```

---

## 🔑 Auth Flow Overview

1. User clicks "Login with Okta"
2. They’re redirected to Okta to authenticate
3. Okta redirects back to `/auth/callback/` with authorization code
4. Backend exchanges the code for ID & access tokens
5. ID token is decoded and used to authenticate the user
6. (Optional) JWT is issued and sent to frontend

---

## 🧩 Auth Views (Example)

### `urls.py`

```python
from django.urls import path
from your_auth_app import views

urlpatterns = [
    path('auth/login/', views.okta_login, name='okta-login'),
    path('auth/callback/', views.okta_callback, name='okta-callback'),
    path('auth/logout/', views.okta_logout, name='okta-logout'),
]
```

### `views.py`

```python
import requests
import json
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import login, logout
from jose import jwt

def okta_login(request):
    return redirect(
        f"{settings.OKTA_ISSUER}/v1/authorize?"
        f"client_id={settings.OKTA_CLIENT_ID}&"
        f"response_type=code&"
        f"scope=openid email profile&"
        f"redirect_uri={settings.OKTA_REDIRECT_URI}&"
        f"state=random123"
    )

def okta_callback(request):
    code = request.GET.get('code')
    token_url = f"{settings.OKTA_ISSUER}/v1/token"
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': settings.OKTA_REDIRECT_URI,
        'client_id': settings.OKTA_CLIENT_ID,
        'client_secret': settings.OKTA_CLIENT_SECRET,
    }

    token_response = requests.post(token_url, data=data, headers=headers)
    token_data = token_response.json()
    id_token = token_data.get("id_token")

    claims = jwt.decode(id_token, options={"verify_signature": False})  # WARNING: For demo only!
    # Verify token properly in production

    # Authenticate user
    from django.contrib.auth.models import User
    user, _ = User.objects.get_or_create(username=claims['sub'], defaults={
        'email': claims.get('email', ''),
        'first_name': claims.get('given_name', ''),
        'last_name': claims.get('family_name', ''),
    })
    login(request, user)

    return redirect('/')

def okta_logout(request):
    logout(request)
    return redirect('/')
```

---

## 🔒 Securing Endpoints

Example of a protected Django REST view:

```python
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def profile(request):
    return Response({"email": request.user.email})
```

---

## 📦 Running the Server

```bash
python manage.py migrate
python manage.py runserver
```

Visit `http://localhost:8000/auth/login/` to start the login flow.

---

## 📄 License

MIT

---

## 🙋‍♂️ Need Help?

Open an issue or contact us at [support@okta.stemgon.com](mailto:support@okta.stemgon.com)

---