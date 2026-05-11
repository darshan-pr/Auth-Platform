from app.models.oauth_consent import OAuthConsent
from app.models.user import User


def test_delete_app_also_deletes_oauth_consents(client, db, admin_token, test_app):
    create_user_response = client.post(
        "/admin/users",
        json={"email": "delete-consent-user@test.com", "app_id": test_app["app_id"]},
        headers=admin_token["headers"],
    )
    assert create_user_response.status_code == 200
    created_user = create_user_response.json()

    db.add(
        OAuthConsent(
            tenant_id=admin_token["tenant_id"],
            user_id=created_user["id"],
            client_id=test_app["app_id"],
            scope="email profile",
            granted=True,
        )
    )
    db.commit()

    delete_response = client.delete(f"/admin/apps/{test_app['app_id']}", headers=admin_token["headers"])
    assert delete_response.status_code == 200

    remaining_user = db.query(User).filter(User.id == created_user["id"]).first()
    assert remaining_user is None

    remaining_consent = (
        db.query(OAuthConsent)
        .filter(
            OAuthConsent.tenant_id == admin_token["tenant_id"],
            OAuthConsent.client_id == test_app["app_id"],
        )
        .first()
    )
    assert remaining_consent is None
