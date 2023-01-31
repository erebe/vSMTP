/*
 * vSMTP mail transfer agent
 * Copyright (C) 2022 viridIT SAS
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program. If not, see https://www.gnu.org/licenses/.
 *
*/

use crate::api::memcached;
use rhai::Engine;

// FIXME: Ignoring tests because they need a running instance of memcached
//        which does not exists in CI environments.

#[ignore]
#[test]
#[should_panic]
fn test_wrong_url() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11444",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    memcached::connect(map.unwrap()).unwrap();
}

#[ignore]
#[test]
fn test_flush() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "flush", "value".into(), 0).unwrap();
    memcached::flush(&mut server).unwrap();
    assert_eq!(
        memcached::get(&mut server, "flush").unwrap().type_name(),
        String::from("()")
    )
}

#[ignore]
#[test]
fn test_non_existing_get() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::delete(&mut server, "non_existing_get").unwrap();
    assert_eq!(
        memcached::get(&mut server, "non_existing_get")
            .unwrap()
            .type_name(),
        String::from("()")
    )
}

#[ignore]
#[test]
fn test_get_string() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "get_string", "value".into(), 0).unwrap();
    assert_eq!(
        memcached::get(&mut server, "get_string")
            .unwrap()
            .type_name(),
        String::from("string")
    )
}

#[ignore]
#[test]
fn test_get_bool() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "get_bool", true.into(), 0).unwrap();
    assert_eq!(
        memcached::get(&mut server, "get_bool").unwrap().type_name(),
        String::from("bool")
    )
}

#[ignore]
#[test]
fn test_get_i64() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    let integer: i64 = 1;
    memcached::set(&mut server, "get_i64", integer.into(), 0).unwrap();
    assert_eq!(
        memcached::get(&mut server, "get_i64").unwrap().type_name(),
        String::from("i64")
    )
}

// #[ignore]#[test]
// fn test_get_u64() {
//     let engine = Engine::new();
//     let map = engine.parse_json(
//         r#"
//             {
//                 "url": "memcache://localhost:11211",
//                 "connections": 1,
//                 "timeout": "1s"
//             }"#,
//         true,
//     );
//     let mut server = memcached::connect(map.unwrap()).unwrap();
//     let unsigned_integer: u64 = 1;
//     memcached::set(&mut server, "key", unsigned_integer.into(), 0).unwrap();
//     dbg!(memcached::get(&mut server, "key").unwrap().type_name());
//     assert_eq!(
//         memcached::get(&mut server, "key").unwrap().type_name(),
//         String::from("u64")
//     )
// }

#[ignore]
#[test]
fn test_get_f64() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    let floating_point: f64 = 1.0;
    memcached::set(&mut server, "get_f64", floating_point.into(), 0).unwrap();
    assert_eq!(
        memcached::get(&mut server, "get_f64").unwrap().type_name(),
        String::from("f64")
    )
}

#[ignore]
#[test]
fn test_get_with_cas() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "get_with_cas", "value".into(), 0).unwrap();
    assert_eq!(
        memcached::get_with_cas(&mut server, "get_with_cas")
            .unwrap()
            .type_name(),
        String::from("map")
    );
    // assert_eq!(
    //     memcached::get_with_cas(&mut server, "get_with_cas").unwrap()["expiration"].type_name(),
    //     String::from("i32")
    // );
    // assert_eq!(
    //     memcached::get_with_cas(&mut server, "get_with_cas").unwrap()["cas_id"].type_name(),
    //     String::from("i64")
    // )
}

#[ignore]
#[test]
fn test_gets() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "gets1", "value1".into(), 0).unwrap();
    memcached::set(&mut server, "gets2", "value2".into(), 0).unwrap();
    memcached::set(&mut server, "gets3", "value3".into(), 0).unwrap();
    assert_eq!(
        memcached::gets(
            &mut server,
            vec!["gets1".into(), "gets2".into(), "gets3".into()]
        )
        .unwrap()
        .type_name(),
        String::from("map")
    )
}

#[ignore]
#[test]
fn test_set() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "set", "value".into(), 0).expect("Set has failed");
    assert_eq!(
        memcached::get(&mut server, "set")
            .unwrap()
            .try_cast::<String>()
            .unwrap(),
        "value"
    );
}

// #[ignore]#[test]
// fn test_cas() {
//     let engine = Engine::new();
//     let map = engine.parse_json(
//         r#"
//             {
//                 "url": "memcache://localhost:11211",
//                 "connections": 1,
//                 "timeout": "1s"
//             }"#,
//         true,
//     );
//     let mut server = memcached::connect(map.unwrap()).unwrap();
//     memcached::set(&mut server, "cas", "value".into(), 0).expect("Set has failed");
//     let cas_id = memcached::get_with_cas(&mut server, "cas").unwrap()["cas_id"];
//     assert!(memcached::cas(&mut server, "cas", "value_2".into(), 0, cas_id.try_cast::<i64>().unwrap()).unwrap());
// }

#[ignore]
#[test]
fn test_add() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::delete(&mut server, "add").unwrap();
    memcached::add(&mut server, "add", "value".into(), 0).unwrap();
    assert_eq!(
        memcached::get(&mut server, "add")
            .unwrap()
            .try_cast::<String>()
            .unwrap(),
        "value"
    );
}

#[ignore]
#[test]
#[should_panic]
fn test_add_already_exist() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "add_2", "value".into(), 0).unwrap();
    memcached::add(&mut server, "add_2", "value".into(), 0).unwrap();
}

#[ignore]
#[test]
fn test_replace() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "replace", "value".into(), 0).unwrap();
    memcached::replace(&mut server, "replace", "new_value".into(), 0).unwrap();
    assert_eq!(
        memcached::get(&mut server, "replace")
            .unwrap()
            .try_cast::<String>()
            .unwrap(),
        "new_value"
    );
}

#[ignore]
#[test]
#[should_panic]
fn test_non_existing_replace() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::delete(&mut server, "replace_2").unwrap();
    memcached::replace(&mut server, "replace_2", "new_value".into(), 0).unwrap();
}

#[ignore]
#[test]
fn test_append() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "append", "value".into(), 0).unwrap();
    memcached::append(&mut server, "append", " and another value".into()).unwrap();
    assert_eq!(
        memcached::get(&mut server, "append")
            .unwrap()
            .try_cast::<String>()
            .unwrap(),
        "value and another value"
    );
}

#[ignore]
#[test]
#[should_panic]
fn test_non_existing_append() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::delete(&mut server, "append_2").unwrap();
    memcached::append(&mut server, "append_2", " and another value".into()).unwrap();
}

#[ignore]
#[test]
fn test_prepend() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "prepend", "value".into(), 0).unwrap();
    memcached::prepend(&mut server, "prepend", "just a value before ".into()).unwrap();
    assert_eq!(
        memcached::get(&mut server, "prepend")
            .unwrap()
            .try_cast::<String>()
            .unwrap(),
        "just a value before value"
    );
}

#[ignore]
#[test]
fn test_delete() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "delete", "value".into(), 0).unwrap();
    assert!(memcached::delete(&mut server, "delete").unwrap());
}

#[ignore]
#[test]
fn test_non_existing_delete() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    assert!(!memcached::delete(&mut server, "delete_2").unwrap());
}

#[ignore]
#[test]
fn test_increment() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "increment", 1.into(), 0).unwrap();
    memcached::increment(&mut server, "increment", 1).unwrap();
    assert_eq!(
        memcached::get(&mut server, "increment")
            .unwrap()
            .try_cast::<i64>()
            .unwrap(),
        2
    );
}

#[ignore]
#[test]
#[should_panic]
fn test_increment_on_bad_value() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "increment_3", "value".into(), 0).unwrap();
    memcached::increment(&mut server, "increment_3", 1).unwrap();
}

#[ignore]
#[test]
fn test_decrement() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "decrement", 1.into(), 0).unwrap();
    memcached::decrement(&mut server, "decrement", 1).unwrap();
    assert_eq!(
        memcached::get(&mut server, "decrement")
            .unwrap()
            .try_cast::<i64>()
            .unwrap(),
        0
    );
}

#[ignore]
#[test]
#[should_panic]
fn test_decrement_on_bad_value() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "decrement_3", "value".into(), 0).unwrap();
    memcached::decrement(&mut server, "decrement_3", 1).unwrap();
}

#[ignore]
#[test]
fn test_touch() {
    let engine = Engine::new();
    let map = engine.parse_json(
        r#"
            {
                "url": "memcache://localhost:11211",
                "connections": 1,
                "timeout": "1s"
            }"#,
        true,
    );
    let mut server = memcached::connect(map.unwrap()).unwrap();
    memcached::set(&mut server, "touch", "value".into(), 5000).unwrap();
    memcached::touch(&mut server, "touch", 0).unwrap();
}
