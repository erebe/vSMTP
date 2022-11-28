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
#[function_name::named]
async fn write_get_and_delete_ctx() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config).unwrap();

    for i in [
        QueueID::Working,
        QueueID::Deliver,
        QueueID::Deferred,
        QueueID::Dead,
    ] {
        let msg_id = format!("{}-{i}", function_name!());
        let mut ctx = local_ctx();
        ctx.mail_from.message_id = msg_id.clone();
        queue_manager.write_ctx(&i, &ctx).await.unwrap();
        let ctx_read = queue_manager.get_ctx(&i, &msg_id).await.unwrap();
        pretty_assertions::assert_eq!(ctx, ctx_read);
        queue_manager.remove_ctx(&i, &msg_id).await.unwrap();
    }
}

#[tokio::test]
#[function_name::named]
async fn write_ctx_after_dir_deleted() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    let i = QueueID::Working;
    let msg_id = format!("{}-{i}", function_name!());
    let mut ctx = local_ctx();
    ctx.mail_from.message_id = msg_id.clone();

    queue_manager.write_ctx(&i, &ctx).await.unwrap();
    let ctx_read = queue_manager.get_ctx(&i, &msg_id).await.unwrap();
    pretty_assertions::assert_eq!(ctx, ctx_read);
    queue_manager.remove_ctx(&i, &msg_id).await.unwrap();
}

#[tokio::test(flavor = "multi_thread")]
#[function_name::named]
async fn write_msg_after_dir_deleted() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    std::fs::remove_dir_all(&config.server.queues.dirpath).unwrap();

    let msg = local_msg();
    queue_manager
        .write_msg(function_name!(), &msg)
        .await
        .unwrap();
    let msg_read = queue_manager.get_msg(function_name!()).await.unwrap();
    pretty_assertions::assert_eq!(msg, msg_read);
    queue_manager.remove_msg(function_name!()).await.unwrap();
}

#[tokio::test]
#[function_name::named]
async fn write_get_and_delete_msg() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config).unwrap();

    let msg = local_msg();
    queue_manager
        .write_msg(function_name!(), &msg)
        .await
        .unwrap();
    let msg_read = queue_manager.get_msg(function_name!()).await.unwrap();
    pretty_assertions::assert_eq!(msg, msg_read);
    queue_manager.remove_msg(function_name!()).await.unwrap();
}

#[tokio::test]
#[function_name::named]
async fn write_get_and_delete_both() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config).unwrap();

    for i in [
        QueueID::Working,
        QueueID::Deliver,
        QueueID::Deferred,
        QueueID::Dead,
    ] {
        let msg_id = format!("{}-{i}", function_name!());
        let mut ctx = local_ctx();
        ctx.mail_from.message_id = msg_id.clone();

        let msg = local_msg();
        queue_manager.write_both(&i, &ctx, &msg).await.unwrap();

        let (ctx_read, msg_read) = queue_manager.get_both(&i, &msg_id).await.unwrap();

        pretty_assertions::assert_eq!(ctx, ctx_read);
        pretty_assertions::assert_eq!(msg, msg_read);

        queue_manager.remove_both(&i, &msg_id).await.unwrap();
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
#[function_name::named]
async fn move_to() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    let mut ctx = local_ctx();
    ctx.mail_from.message_id = function_name!().to_string();

    queue_manager
        .get_ctx(&QueueID::Working, function_name!())
        .await
        .unwrap_err();
    queue_manager
        .get_ctx(&QueueID::Deliver, function_name!())
        .await
        .unwrap_err();

    queue_manager
        .write_ctx(&QueueID::Working, &ctx)
        .await
        .unwrap();

    queue_manager
        .get_ctx(&QueueID::Working, function_name!())
        .await
        .unwrap();
    queue_manager
        .get_ctx(&QueueID::Deliver, function_name!())
        .await
        .unwrap_err();

    queue_manager
        .move_to(&QueueID::Working, &QueueID::Deliver, &ctx)
        .await
        .unwrap();

    queue_manager
        .get_ctx(&QueueID::Working, function_name!())
        .await
        .unwrap_err();
    queue_manager
        .get_ctx(&QueueID::Deliver, function_name!())
        .await
        .unwrap();
}

#[tokio::test]
#[function_name::named]
async fn move_to_from_id() {
    let config = arc!(local_test());
    let queue_manager = vqueue::temp::QueueManager::init(config.clone()).unwrap();

    let mut ctx = local_ctx();
    ctx.mail_from.message_id = function_name!().to_string();

    queue_manager
        .write_ctx(&QueueID::Deliver, &ctx)
        .await
        .unwrap();
    queue_manager
        .move_to_from_id(&QueueID::Deliver, &QueueID::Working, function_name!())
        .await
        .unwrap();

    queue_manager
        .get_ctx(&QueueID::Deliver, function_name!())
        .await
        .unwrap_err();
    queue_manager
        .get_ctx(&QueueID::Working, function_name!())
        .await
        .unwrap();
}
