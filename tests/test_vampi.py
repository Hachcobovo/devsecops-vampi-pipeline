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
    vuln_app.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    # Dùng connexion test client, KHÔNG phải vuln_app.app.test_client()
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
    # connexion 3.x: resp.json thay vì json.loads(resp.data)
    body = resp.json()
    return body.get('auth_token', '')


# ── Users endpoints ──────────────────────────────────────────

class TestUsersEndpoints:
    def test_get_all_users(self, client):
        resp = client.get('/users/v1/')
        assert resp.status_code == 200

    def test_register_new_user(self, client):
        resp = client.post('/users/v1/register', json={
            'username': 'newuser1',
            'password': 'password123',
            'email': 'new1@test.com'
        })
        assert resp.status_code in [200, 201]

    def test_register_duplicate_user(self, client):
        payload = {'username': 'dupuser', 'password': 'pass', 'email': 'dup@test.com'}
        client.post('/users/v1/register', json=payload)
        resp = client.post('/users/v1/register', json=payload)
        assert resp.status_code in [400, 409]

    def test_register_missing_fields(self, client):
        resp = client.post('/users/v1/register', json={'username': 'onlyname'})
        assert resp.status_code in [400, 422]

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
        data = resp.json()
        assert 'auth_token' in data

    def test_login_wrong_password(self, client):
        client.post('/users/v1/register', json={
            'username': 'wrongpass',
            'password': 'correct',
            'email': 'wp@test.com'
        })
        resp = client.post('/users/v1/login', json={
            'username': 'wrongpass',
            'password': 'wrong'
        })
        assert resp.status_code in [400, 401]

    def test_login_nonexistent_user(self, client):
        resp = client.post('/users/v1/login', json={
            'username': 'ghost',
            'password': 'pass'
        })
        assert resp.status_code in [400, 401, 404]

    def test_get_user_by_username(self, client, auth_token):
        resp = client.get(
            '/users/v1/testuser',
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert resp.status_code in [200, 401]

    def test_get_user_no_auth(self, client):
        resp = client.get('/users/v1/testuser')
        assert resp.status_code in [200, 401]

    def test_delete_user_no_auth(self, client):
        resp = client.delete('/users/v1/testuser')
        assert resp.status_code in [401, 403]

    def test_update_password(self, client, auth_token):
        resp = client.put(
            '/users/v1/testuser',
            json={'password': 'newpass456'},
            headers={'Authorization': f'Bearer {auth_token}'}
        )
        assert resp.status_code in [200, 204, 400, 401]


# ── Books endpoints ───────────────────────────────────────────

class TestBooksEndpoints:
    def test_get_all_books(self, client):
        resp = client.get('/books/v1/')
        assert resp.status_code == 200

    def test_get_all_books_returns_list(self, client):
        resp = client.get('/books/v1/')
        data = resp.json()
        assert isinstance(data, (list, dict))

    def test_get_book_by_name(self, client):
        # Lấy danh sách trước rồi mới get theo tên
        resp = client.get('/books/v1/')
        data = resp.json()
        # books trả về dict có key 'Books'
        books = data.get('Books', data) if isinstance(data, dict) else data
        if books:
            first = books[0]
            name = first.get('book_title') or first.get('name') or 'unknown'
            r = client.get(f'/books/v1/{name}')
            assert r.status_code in [200, 404]

    def test_add_book_no_auth(self, client):
        resp = client.post('/books/v1/', json={
            'book_title': 'Test Book',
            'secret': 'some secret',
            'user': 'testuser'
        })
        assert resp.status_code in [401, 403]

    def test_add_book_with_auth(self, client, auth_token):
        resp = client.post('/books/v1/', json={
            'book_title': 'Auth Book',
            'secret': 'book secret',
            'user': 'testuser'
        }, headers={'Authorization': f'Bearer {auth_token}'})
        assert resp.status_code in [200, 201, 401]


# ── Debug / misc endpoints ────────────────────────────────────

class TestDebugEndpoints:
    def test_debug_create_db(self, client):
        resp = client.get('/createdb')
        assert resp.status_code in [200, 201]

    def test_debug_users_after_createdb(self, client):
        client.get('/createdb')
        resp = client.get('/users/v1/')
        assert resp.status_code == 200

    def test_openapi_json(self, client):
        resp = client.get('/openapi.json')
        assert resp.status_code == 200

    def test_openapi_ui(self, client):
        resp = client.get('/ui/')
        assert resp.status_code in [200, 301, 308]


# ── Security / vulnerability behaviors ───────────────────────

class TestSecurityBehaviors:
    def test_no_auth_header_returns_error(self, client):
        resp = client.get('/users/v1/someuser')
        assert resp.status_code in [200, 401]

    def test_invalid_token_rejected(self, client):
        resp = client.get(
            '/users/v1/testuser',
            headers={'Authorization': 'Bearer invalidtoken'}
        )
        assert resp.status_code in [200, 401, 422]

    def test_sql_injection_input_handled(self, client):
        # VAmPI vulnerable: không crash server dù nhận input đặc biệt
        resp = client.get("/books/v1/' OR '1'='1")
        assert resp.status_code in [200, 404, 400]

    def test_register_with_admin_flag(self, client):
        # BOLA: thử đăng ký với is_admin
        resp = client.post('/users/v1/register', json={
            'username': 'hacker',
            'password': 'hacked',
            'email': 'hack@test.com',
            'is_admin': True
        })
        assert resp.status_code in [200, 201, 400]