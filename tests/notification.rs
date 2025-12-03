mod common;
use common::*;
use reqwest::StatusCode;

#[tokio::test]
async fn test_list_notifications() {
    let client = client();
    let params = [
        ("limit", "30"),
    ];
    let res = client.get(format!("{}/xrpc/app.bsky.notification.listNotifications", BASE_URL))
        .query(&params)
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_get_unread_count() {
    let client = client();
    let res = client.get(format!("{}/xrpc/app.bsky.notification.getUnreadCount", BASE_URL))
        .bearer_auth(AUTH_TOKEN)
        .send()
        .await
        .expect("Failed to send request");

    assert_eq!(res.status(), StatusCode::OK);
}
