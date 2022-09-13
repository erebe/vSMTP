use crate::config::local_ctx;
use crate::config::local_msg;
use crate::config::local_test;
use vqueue::GenericQueueManager;
use vqueue::QueueID;

#[tokio::test]
async fn init_success() {
    let config = local_test();
    let config = std::sync::Arc::new(config);
    let queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config.clone()).unwrap();
    assert_eq!(format!("{:?}", queue_manager), "QueueManager { .. }");
    pretty_assertions::assert_eq!(*queue_manager.get_config().await, *config);
}

#[test]
fn init_fail() {
    let mut config = local_test();
    config.server.queues.dirpath = "/var/spool/vsmtp".into(); // no write access
    let config = std::sync::Arc::new(config);
    let _queue_manager =
        <vqueue::fs::QueueManager as vqueue::GenericQueueManager>::init(config).unwrap_err();
}

#[tokio::test]
async fn write_get_and_delete_ctx() {
    let config = local_test();
    let config = std::sync::Arc::new(config);
    let queue_manager = vqueue::fs::QueueManager::init(config).unwrap();

    for i in [
        QueueID::Working,
        QueueID::Deliver,
        QueueID::Deferred,
        QueueID::Dead,
    ] {
        let msg_id = format!("write_get_and_delete-{i}");
        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.clone());
        queue_manager.write_ctx(&i, &ctx).await.unwrap();
        let ctx_read = queue_manager.get_ctx(&i, &msg_id).unwrap();
        pretty_assertions::assert_eq!(ctx, ctx_read);
        queue_manager.remove_ctx(&i, &msg_id).await.unwrap();
    }
}

#[tokio::test]
async fn write_ctx_after_dir_deleted() {
    let mut config = local_test();
    config.server.queues.dirpath = "./tmp/spool2".into();
    let config = std::sync::Arc::new(config);
    let queue_manager = vqueue::fs::QueueManager::init(config.clone()).unwrap();

    let i = QueueID::Working;
    let msg_id = format!("write_ctx_after_dir_deleted-{i}");
    let mut ctx = local_ctx();
    ctx.metadata.message_id = Some(msg_id.clone());

    let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

    queue_manager.write_ctx(&i, &ctx).await.unwrap();
    let ctx_read = queue_manager.get_ctx(&i, &msg_id).unwrap();
    pretty_assertions::assert_eq!(ctx, ctx_read);
    queue_manager.remove_ctx(&i, &msg_id).await.unwrap();
}

#[tokio::test]
async fn write_msg_after_dir_deleted() {
    let mut config = local_test();
    config.server.queues.dirpath = "./tmp/spool3".into();
    let config = std::sync::Arc::new(config);
    let queue_manager = vqueue::fs::QueueManager::init(config.clone()).unwrap();

    let msg_id = "write_msg_after_dir_deleted".to_string();

    std::fs::remove_dir_all(&config.server.queues.dirpath).unwrap();

    let msg = local_msg();
    queue_manager.write_msg(&msg_id, &msg).unwrap();
    let msg_read = queue_manager.get_msg(&msg_id).unwrap();
    pretty_assertions::assert_eq!(msg, msg_read);
    queue_manager.remove_msg(&msg_id).await.unwrap();
}

#[tokio::test]
async fn write_get_and_delete_msg() {
    let config = local_test();
    let config = std::sync::Arc::new(config);
    let queue_manager = vqueue::fs::QueueManager::init(config).unwrap();

    let msg_id = "write_get_and_delete-msg".to_string();
    let msg = local_msg();
    queue_manager.write_msg(&msg_id, &msg).unwrap();
    let msg_read = queue_manager.get_msg(&msg_id).unwrap();
    pretty_assertions::assert_eq!(msg, msg_read);
    queue_manager.remove_msg(&msg_id).await.unwrap();
}

#[tokio::test]
async fn write_get_and_delete_both() {
    let config = local_test();
    let config = std::sync::Arc::new(config);
    let queue_manager = vqueue::fs::QueueManager::init(config).unwrap();

    for i in [
        QueueID::Working,
        QueueID::Deliver,
        QueueID::Deferred,
        QueueID::Dead,
    ] {
        let msg_id = format!("write_get_and_delete_both-{i}");
        let mut ctx = local_ctx();
        ctx.metadata.message_id = Some(msg_id.clone());

        let msg = local_msg();
        queue_manager.write_both(&i, &ctx, &msg).await.unwrap();

        let (ctx_read, msg_read) = queue_manager.get_both(&i, &msg_id).unwrap();

        pretty_assertions::assert_eq!(ctx, ctx_read);
        pretty_assertions::assert_eq!(msg, msg_read);

        queue_manager.remove_both(&i, &msg_id).await.unwrap();
    }
}

#[tokio::test]
async fn move_same_queue() {
    let config = local_test();
    let config = std::sync::Arc::new(config);
    let queue_manager = vqueue::fs::QueueManager::init(config.clone()).unwrap();

    let ctx = local_ctx();
    queue_manager
        .move_to(&QueueID::Working, &QueueID::Working, &ctx)
        .await
        .unwrap_err();
}

#[tokio::test]
async fn move_to() {
    let mut config = local_test();
    config.server.queues.dirpath = "./tmp/spool_move_to".into();
    let _rm = std::fs::remove_dir_all(&config.server.queues.dirpath);

    let config = std::sync::Arc::new(config);
    let queue_manager = vqueue::fs::QueueManager::init(config.clone()).unwrap();

    let mut ctx = local_ctx();
    let msg_id = "msg_moved";
    ctx.metadata.message_id = Some(msg_id.to_string());

    let working_path = config
        .server
        .queues
        .dirpath
        .join(format!("working/{msg_id}.json"));
    let deliver_path = config
        .server
        .queues
        .dirpath
        .join(format!("deliver/{msg_id}.json"));

    assert!(!working_path.exists());
    assert!(!deliver_path.exists());

    queue_manager
        .write_ctx(&QueueID::Working, &ctx)
        .await
        .unwrap();

    assert!(working_path.exists());
    assert!(!deliver_path.exists());

    queue_manager
        .move_to(&QueueID::Working, &QueueID::Deliver, &ctx)
        .await
        .unwrap();

    assert!(!working_path.exists());
    assert!(deliver_path.exists());
}
