use crate::config::local_ctx;
use crate::config::local_msg;
use crate::config::local_test;
use vqueue::GenericQueueManager;
use vqueue::QueueID;

#[tokio::test]
async fn init_success() {
    let config = arc!(local_test());
    let queue_manager =
        <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();
    assert_eq!(format!("{:?}", queue_manager), "TempQueueManager { .. }");
    pretty_assertions::assert_eq!(*queue_manager.get_config(), *config);
}

#[tokio::test]
async fn init_fail() {
    let mut config = local_test();
    config.server.queues.dirpath = "/var/spool/vsmtp".into(); // no write access
    let config = arc!(config);
    let _queue_manager =
        <vqueue::temp::QueueManager as vqueue::GenericQueueManager>::init(config).unwrap_err();
}

#[tokio::test]
async fn write_get_and_delete_ctx() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config).unwrap();

    for i in [
        QueueID::Working,
        QueueID::Deliver,
        QueueID::Deferred,
        QueueID::Dead,
    ] {
        let msg_uuid = uuid::Uuid::new_v4();
        let mut ctx = local_ctx();
        ctx.mail_from.message_uuid = msg_uuid;
        queue_manager.write_ctx(&i, &ctx).await.unwrap();
        let ctx_read = queue_manager.get_ctx(&i, &msg_uuid).await.unwrap();
        pretty_assertions::assert_eq!(ctx, ctx_read);
        queue_manager.remove_ctx(&i, &msg_uuid).await.unwrap();
    }
}

#[tokio::test]
async fn write_ctx_after_dir_deleted() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    let i = QueueID::Working;
    let msg_uuid = uuid::Uuid::new_v4();
    let mut ctx = local_ctx();
    ctx.mail_from.message_uuid = msg_uuid;

    queue_manager.write_ctx(&i, &ctx).await.unwrap();
    let ctx_read = queue_manager.get_ctx(&i, &msg_uuid).await.unwrap();
    pretty_assertions::assert_eq!(ctx, ctx_read);
    queue_manager.remove_ctx(&i, &msg_uuid).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn write_msg_after_dir_deleted() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    std::fs::remove_dir_all(&config.server.queues.dirpath).unwrap();
    let msg_uuid = uuid::Uuid::new_v4();

    let msg = local_msg();
    queue_manager.write_msg(&msg_uuid, &msg).await.unwrap();
    let msg_read = queue_manager.get_msg(&msg_uuid).await.unwrap();
    pretty_assertions::assert_eq!(msg, msg_read);
    queue_manager.remove_msg(&msg_uuid).await.unwrap();
}

#[tokio::test]
async fn write_get_and_delete_msg() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config).unwrap();
    let msg_uuid = uuid::Uuid::new_v4();

    let msg = local_msg();
    queue_manager.write_msg(&msg_uuid, &msg).await.unwrap();
    let msg_read = queue_manager.get_msg(&msg_uuid).await.unwrap();
    pretty_assertions::assert_eq!(msg, msg_read);
    queue_manager.remove_msg(&msg_uuid).await.unwrap();
}

#[tokio::test]
async fn write_get_and_delete_both() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config).unwrap();

    for i in [
        QueueID::Working,
        QueueID::Deliver,
        QueueID::Deferred,
        QueueID::Dead,
    ] {
        let msg_uuid = uuid::Uuid::new_v4();
        let mut ctx = local_ctx();
        ctx.mail_from.message_uuid = msg_uuid;

        let msg = local_msg();
        queue_manager.write_both(&i, &ctx, &msg).await.unwrap();

        let (ctx_read, msg_read) = queue_manager.get_both(&i, &msg_uuid).await.unwrap();

        pretty_assertions::assert_eq!(ctx, ctx_read);
        pretty_assertions::assert_eq!(msg, msg_read);

        queue_manager.remove_both(&i, &msg_uuid).await.unwrap();
    }
}

#[tokio::test]
async fn move_same_queue() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    let ctx = local_ctx();
    queue_manager
        .move_to(&QueueID::Working, &QueueID::Working, &ctx)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn move_to() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    let mut ctx = local_ctx();
    let msg_uuid = uuid::Uuid::new_v4();

    ctx.mail_from.message_uuid = msg_uuid;

    queue_manager
        .get_ctx(&QueueID::Working, &msg_uuid)
        .await
        .unwrap_err();
    queue_manager
        .get_ctx(&QueueID::Deliver, &msg_uuid)
        .await
        .unwrap_err();

    queue_manager
        .write_ctx(&QueueID::Working, &ctx)
        .await
        .unwrap();

    queue_manager
        .get_ctx(&QueueID::Working, &msg_uuid)
        .await
        .unwrap();
    queue_manager
        .get_ctx(&QueueID::Deliver, &msg_uuid)
        .await
        .unwrap_err();

    queue_manager
        .move_to(&QueueID::Working, &QueueID::Deliver, &ctx)
        .await
        .unwrap();

    queue_manager
        .get_ctx(&QueueID::Working, &msg_uuid)
        .await
        .unwrap_err();
    queue_manager
        .get_ctx(&QueueID::Deliver, &msg_uuid)
        .await
        .unwrap();
}

#[tokio::test]
async fn move_to_from_id() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    let mut ctx = local_ctx();
    let msg_uuid = uuid::Uuid::new_v4();
    ctx.mail_from.message_uuid = msg_uuid;

    queue_manager
        .write_ctx(&QueueID::Deliver, &ctx)
        .await
        .unwrap();
    queue_manager
        .move_to_from_id(&QueueID::Deliver, &QueueID::Working, &msg_uuid)
        .await
        .unwrap();

    queue_manager
        .get_ctx(&QueueID::Deliver, &msg_uuid)
        .await
        .unwrap_err();
    queue_manager
        .get_ctx(&QueueID::Working, &msg_uuid)
        .await
        .unwrap();
}
