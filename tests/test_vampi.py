import pytest
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

os.environ.setdefault('vulnerable', '1')
os.environ.setdefault('tokentimetolive', '3600')
os.environ.setdefault('SECRET_KEY', 'test-secret-key-for-coverage')


@pytest.fixture(scope='session')
def client():
    from config import vuln_app, db
    vuln_app.app.config['TESTING'] = True
    with vuln_app.test_client() as c:
        with vuln_app.app.app_context():
            db.create_all()
        yield c


@pytest.fixture(scope='session')
def auth_token(client):
    client.post('/users/v1/register', json={
        'username': 'testuser',
        'password': 'testpass123',
        'email': 'test@test.com'
    })
    resp = client.post('/users/v1/login', json={
        'username': 'testuser',
        'password': 'testpass123'
    })
    body = json.loads(resp.data if hasattr(resp, 'data') else resp.content)
    return body.get('auth_token', '')


class TestDebugEndpoints:
    def test_createdb(self, client):
        resp = client.get('/createdb')
        assert resp.status_code in [200, 201]

    def test_openapi_json(self, client):
        resp = client.get('/openapi.json')
        assert resp.status_code == 200

    def test_openapi_ui(self, client):
        resp = client.get('/ui/')
        assert resp.status_code in [200, 301, 308]


class TestUsersEndpoints:
    def test_get_all_users(self, client):
        resp = client.get('/users/v1/')
        assert resp.status_code == 200

    def test_get_all_users_returns_data(self, client):
        resp = client.get('/users/v1/')
        body = json.loads(resp.data if hasattr(resp, 'data') else resp.content)
        assert body is not None

    def test_register_success(self, client):
        resp = client.post('/users/v1/register', json={
            'username': 'newuser1',
            'password': 'password123',
            'email': 'new1@test.com'
        })
        assert resp.status_code in [200, 201]

    def test_register_missing_password(self, client):
        resp = client.post('/users/v1/register', json={
            'username': 'nopassuser',
            'email': 'nop@test.com'
        })
        assert resp.status_code in [400, 422]

    def test_register_missing_email(self, client):
        resp = client.post('/users/v1/register', json={
            'username': 'noemailuser',
            'password': 'pass123'
        })
        assert resp.status_code in [400, 422]

    def test_register_duplicate_username(self, client):
        payload = {
            'username': 'dupuser',
            'password': 'pass123',
            'email': 'dup@test.com'
        }
        client.post('/users/v1/register', json=payload)
        resp = client.post('/users/v1/register', json=payload)
        assert resp.status_code in [400, 409]

    def test_login_success(self, client):
        client.post('/users/v1/register', json={
            'username': 'loginuser',
            'password': 'mypassword',
            'email': 'login@test.com'
        })
        resp = client.post('/users/v1/login', json={
            'username': 'loginuser',
            'password': 'mypassword'
        })
        assert resp.status_code == 200
        body = json.loads(resp.data if hasattr(resp, 'data') else resp.content)
        assert 'auth_token' in body

    def test_login_wrong_password(self, client):
        client.post('/users/v1/register', json={
            'username': 'wrongpassuser',
            'password': 'correct123',
            'email': 'wp@test.com'
        })
        resp = client.post('/users/v1/login', json={
            'username': 'wrongpassuser',
            'password': 'wrongpass'
        })
        assert resp.status_code in [400, 401]

    def test_login_nonexistent_user(self, client):
        resp = client.post('/users/v1/login', json={
            'username': 'ghostuser99',
            'password': 'pass'
        })
        assert resp.status_code in [400, 401, 404]

    def test_get_user_no_auth(self, client):
        resp = client.get('/users/v1/admin')
        assert resp.status_code in [200, 401, 403]

    def test_get_user_with_auth(self, client, auth_token):
        resp = client.get(
            '/users/v1/testuser',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert resp.status_code in [200, 401, 403]

    def test_delete_user_no_auth(self, client):
        resp = client.delete('/users/v1/testuser')
        assert resp.status_code in [401, 403]

    def test_update_password_with_auth(self, client, auth_token):
        resp = client.put(
            '/users/v1/testuser',
            json={'password': 'newpass456'},
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert resp.status_code in [200, 204, 400, 401, 403]

    def test_update_password_no_auth(self, client):
        resp = client.put(
            '/users/v1/testuser',
            json={'password': 'newpass456'}
        )
        assert resp.status_code in [400, 401, 403]


class TestBooksEndpoints:
    def test_get_all_books(self, client):
        resp = client.get('/books/v1/')
        assert resp.status_code == 200

    def test_get_all_books_structure(self, client):
        resp = client.get('/books/v1/')
        body = json.loads(resp.data if hasattr(resp, 'data') else resp.content)
        assert isinstance(body, (list, dict))

    def test_get_book_not_found(self, client):
        resp = client.get('/books/v1/nonexistentbook99999')
        assert resp.status_code in [200, 404]

    def test_add_book_no_auth(self, client):
        resp = client.post('/books/v1/', json={
            'book_title': 'Unauthorized Book',
            'secret': 'some secret',
            'user': 'testuser'
        })
        assert resp.status_code in [401, 403]

    def test_add_book_with_auth(self, client, auth_token):
        resp = client.post('/books/v1/', json={
            'book_title': 'Authorized Book',
            'secret': 'book secret here',
            'user': 'testuser'
        }, headers={'Authorization': f'Bearer {auth_token}'})
        assert resp.status_code in [200, 201, 401]

    def test_get_book_after_add(self, client, auth_token):
        client.post('/books/v1/', json={
            'book_title': 'FindableBook',
            'secret': 'secret content',
            'user': 'testuser'
        }, headers={'Authorization': f'Bearer {auth_token}'})
        resp = client.get('/books/v1/FindableBook')
        assert resp.status_code in [200, 404]


class TestSecurityBehaviors:
    def test_invalid_token_format(self, client):
        resp = client.get(
            '/users/v1/admin',
            headers={'Authorization': 'Bearer thisisnotavalidtoken'}
        )
        assert resp.status_code in [200, 401, 403, 422]

    def test_malformed_auth_header(self, client):
        resp = client.get(
            '/users/v1/admin',
            headers={'Authorization': 'NotBearer something'}
        )
        assert resp.status_code in [200, 401, 403]

    def test_register_with_admin_flag(self, client):
        resp = client.post('/users/v1/register', json={
            'username': 'hackeruser',
            'password': 'hacked123',
            'email': 'hack@test.com',
            'is_admin': True
        })
        assert resp.status_code in [200, 201, 400]

    def test_sql_injection_in_book_name(self, client):
        resp = client.get("/books/v1/test' OR '1'='1")
        assert resp.status_code in [200, 404, 400]

    def test_empty_login_body(self, client):
        resp = client.post('/users/v1/login', json={})
        assert resp.status_code in [400, 401, 422]

    def test_empty_register_body(self, client):
        resp = client.post('/users/v1/register', json={})
        assert resp.status_code in [400, 422]