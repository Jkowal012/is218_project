from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token  # Import your FastAPI app

# Example of a test function using the async_client fixture
@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    # Define user data for the test
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    # Send a POST request to create a user
    response = await async_client.post("/users/", json=user_data, headers=headers)
    # Asserts
    assert response.status_code == 403

# You can similarly refactor other test functions to use the async_client fixture
@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

@pytest.mark.asyncio
async def test_update_user_email_access_denied(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_email_access_allowed(async_client, admin_user, admin_token):
    updated_data = {"email": f"updated_{admin_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]


@pytest.mark.asyncio
async def test_delete_user(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{admin_user.id}", headers=headers)
    assert delete_response.status_code == 204
    # Verify the user is deleted
    fetch_response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert fetch_response.status_code == 404

@pytest.mark.asyncio
async def test_create_user_duplicate_email(async_client, verified_user):
    user_data = {
        "email": verified_user.email,
        "password": "AnotherPassword123!",
        "role": UserRole.ADMIN.name
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 400
    assert "Email already exists" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_create_user_invalid_email(async_client):
    user_data = {
        "email": "notanemail",
        "password": "ValidPassword123!",
    }
    response = await async_client.post("/register/", json=user_data)
    assert response.status_code == 422

import pytest
from app.services.jwt_service import decode_token
from urllib.parse import urlencode

@pytest.mark.asyncio
async def test_login_success(async_client, verified_user):
    # Attempt to login with the test user
    form_data = {
        "username": verified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    
    # Check for successful login response
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"

    # Use the decode_token method from jwt_service to decode the JWT
    decoded_token = decode_token(data["access_token"])
    assert decoded_token is not None, "Failed to decode token"
    assert decoded_token["role"] == "AUTHENTICATED", "The user role should be AUTHENTICATED"

@pytest.mark.asyncio
async def test_login_user_not_found(async_client):
    form_data = {
        "username": "nonexistentuser@here.edu",
        "password": "DoesNotMatter123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_incorrect_password(async_client, verified_user):
    form_data = {
        "username": verified_user.email,
        "password": "IncorrectPassword123!"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401
    assert "Incorrect email or password." in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_login_unverified_user(async_client, unverified_user):
    form_data = {
        "username": unverified_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 401

@pytest.mark.asyncio
async def test_login_locked_user(async_client, locked_user):
    form_data = {
        "username": locked_user.email,
        "password": "MySuperPassword$1234"
    }
    response = await async_client.post("/login/", data=urlencode(form_data), headers={"Content-Type": "application/x-www-form-urlencoded"})
    assert response.status_code == 400
    assert "Account locked due to too many failed login attempts." in response.json().get("detail", "")
@pytest.mark.asyncio
async def test_delete_user_does_not_exist(async_client, admin_token):
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"  # Valid UUID format
    headers = {"Authorization": f"Bearer {admin_token}"}
    delete_response = await async_client.delete(f"/users/{non_existent_user_id}", headers=headers)
    assert delete_response.status_code == 404

@pytest.mark.asyncio
async def test_update_user_github(async_client, admin_user, admin_token):
    updated_data = {"github_profile_url": "http://www.github.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["github_profile_url"] == updated_data["github_profile_url"]

@pytest.mark.asyncio
async def test_update_user_linkedin(async_client, admin_user, admin_token):
    updated_data = {"linkedin_profile_url": "http://www.linkedin.com/kaw393939"}
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.put(f"/users/{admin_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["linkedin_profile_url"] == updated_data["linkedin_profile_url"]

@pytest.mark.asyncio
async def test_list_users_as_admin(async_client, admin_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {admin_token}"}
    )
    assert response.status_code == 200
    assert 'items' in response.json()

@pytest.mark.asyncio
async def test_list_users_as_manager(async_client, manager_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {manager_token}"}
    )
    assert response.status_code == 200

@pytest.mark.asyncio
async def test_list_users_unauthorized(async_client, user_token):
    response = await async_client.get(
        "/users/",
        headers={"Authorization": f"Bearer {user_token}"}
    )
    assert response.status_code == 403  # Forbidden, as expected for regular user

@pytest.mark.asyncio
async def test_upgrade_professional_status_as_admin(async_client: AsyncClient, admin_user, admin_token, verified_user, db_session):
    # Admin upgrading a verified user's professional status
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.post(f"/users/{verified_user.id}/upgrade-professional", headers=headers)
    assert response.status_code == 200, "Admin should be able to upgrade a user's professional status."
    data = response.json()
    assert data["is_professional"] is True, "User should now be professional."
    # Check timestamp is updated
    user_in_db = await db_session.get(User, verified_user.id)
    assert user_in_db.professional_status_updated_at is not None, "Timestamp should be set after upgrade."

@pytest.mark.asyncio
async def test_upgrade_professional_status_as_manager(async_client: AsyncClient, manager_user, manager_token, verified_user, db_session):
    # Manager upgrading a verified user's professional status
    headers = {"Authorization": f"Bearer {manager_token}"}
    response = await async_client.post(f"/users/{verified_user.id}/upgrade-professional", headers=headers)
    assert response.status_code == 200, "Manager should be able to upgrade a user's professional status."
    data = response.json()
    assert data["is_professional"] is True
    user_in_db = await db_session.get(User, verified_user.id)
    assert user_in_db.professional_status_updated_at is not None

@pytest.mark.asyncio
async def test_upgrade_professional_status_as_user_forbidden(async_client: AsyncClient, user, user_token, verified_user):
    # A normal user should not be allowed to upgrade someone else's professional status
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.post(f"/users/{verified_user.id}/upgrade-professional", headers=headers)
    assert response.status_code == 403, "Normal user should not be able to upgrade professional status."

@pytest.mark.asyncio
async def test_upgrade_professional_status_user_not_found(async_client: AsyncClient, admin_token):
    # Attempting to upgrade a non-existent user
    non_existent_user_id = "00000000-0000-0000-0000-000000000000"
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.post(f"/users/{non_existent_user_id}/upgrade-professional", headers=headers)
    assert response.status_code == 404, "Should return 404 if user not found."

@pytest.mark.asyncio
async def test_update_user_profile_as_admin(async_client: AsyncClient, admin_user, admin_token, verified_user, db_session):
    # Admin can update any field, including restricted ones
    headers = {"Authorization": f"Bearer {admin_token}"}
    updated_data = {
        "email": "new_email@example.com",
        "nickname": "new_nickname",
        "role": "ADMIN",  # Admin can update role
        "bio": "Updated bio"
    }
    response = await async_client.put(f"/users/{verified_user.id}/profile", json=updated_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "new_email@example.com"
    assert data["nickname"] == "new_nickname"
    assert data["role"] == "ADMIN"  # Should be updated by an admin
    user_in_db = await db_session.get(User, verified_user.id)
    assert user_in_db.email == "new_email@example.com"
    assert user_in_db.nickname == "new_nickname"
    assert user_in_db.role == UserRole.ADMIN

@pytest.mark.asyncio
async def test_update_user_profile_as_manager(async_client: AsyncClient, manager_user, manager_token, verified_user, db_session):
    # Manager can also update restricted fields if desired
    headers = {"Authorization": f"Bearer {manager_token}"}
    updated_data = {
        "bio": "Manager updated bio",
        "role": "MANAGER"
    }
    response = await async_client.put(f"/users/{verified_user.id}/profile", json=updated_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["bio"] == "Manager updated bio"
    assert data["role"] == "MANAGER"
    user_in_db = await db_session.get(User, verified_user.id)
    assert user_in_db.role == UserRole.MANAGER

@pytest.mark.asyncio
async def test_update_own_profile_as_user(async_client: AsyncClient, verified_user, user_token, db_session):
    # A normal authenticated user updating their own profile
    # They cannot update restricted fields (role, is_locked, is_professional)
    headers = {"Authorization": f"Bearer {user_token}"}
    # The verified_user and user_token should correspond to the same user in the fixtures
    # If not, you'd need a fixture that creates a verified_user and uses that same user for the token.
    # Here we assume `user_token` and `verified_user` represent the same user. If not, create a fixture that ensures that.
    updated_data = {
        "email": "user_self_update@example.com",
        "role": "ADMIN",  # user should not be able to update this
        "is_professional": True,
        "bio": "User updated bio"
    }
    response = await async_client.put(f"/users/{verified_user.id}/profile", json=updated_data, headers=headers)
    assert response.status_code == 200
    data = response.json()
    # Check that restricted fields are not updated
    assert data["role"] != "ADMIN"
    assert data["is_professional"] is not True
    # The allowed field 'bio' should be updated
    assert data["bio"] == "User updated bio"
    # The email is allowed to be updated by the user
    assert data["email"] == "user_self_update@example.com"

    user_in_db = await db_session.get(User, verified_user.id)
    assert user_in_db.email == "user_self_update@example.com"
    # role should remain unchanged (i.e., not ADMIN)
    assert user_in_db.role != UserRole.ADMIN
    # is_professional should remain unchanged (default or whatever it was)
    assert not user_in_db.is_professional