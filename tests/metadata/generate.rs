use std::fs::File;
//use std::io::prelude::*;
use std::collections::HashMap;
use std::path::Path;
//use tuf::crypto::{HashAlgorithm, KeyId, PrivateKey, SignatureScheme};
//use serde_json::{Result, Value};
use futures_executor::block_on;
use tuf::crypto::{HashAlgorithm, PrivateKey, SignatureScheme};
use tuf::interchange::Json;
use tuf::metadata::{
    MetadataPath, MetadataVersion, Role, RootMetadataBuilder, SnapshotMetadataBuilder, TargetPath,
    TargetsMetadataBuilder, TimestampMetadataBuilder, VirtualTargetPath,
};
use tuf::repository::{FileSystemRepository, FileSystemRepositoryBuilder, Repository};
use tuf::Result;

// TODO pass these in instead.
// TODO: use the same keys as the go-tuf repo?
const ED25519_1_PK8: &'static [u8] = include_bytes!("../ed25519/ed25519-1.pk8.der");
const ED25519_2_PK8: &'static [u8] = include_bytes!("../ed25519/ed25519-2.pk8.der");
const ED25519_3_PK8: &'static [u8] = include_bytes!("../ed25519/ed25519-3.pk8.der");
const ED25519_4_PK8: &'static [u8] = include_bytes!("../ed25519/ed25519-4.pk8.der");
//const keys_path = "./keys.json";

// Read the keys in from the json file copied from the Go repo.
// TODO: would it be better to add a private key to the TUF keys field?
// Do I have to re-encode these mofos?
/*fn keys_from_json(path: &str) -> serde_json::Result<()> {
    let f = File::open(path).expect("failed to open keys file");
    let mut contents = String::new();
    f.read_to_string(&mut contents).expect("failed to read keys");
    let keys : serde_json::Value = serde_json::from_str(contents).expect("serde failed");
    // elf it all, I might not use this anyway.
}*/

// TODO change array to something more extendable? depends how keys get stored. maybe a vec.
fn test_keys() -> HashMap<&'static str, [PrivateKey; 2]> {
    let root_key_0 = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
    let root_key_1 = PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
    let snapshot_key = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap();
    let snapshot_key_1 = PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap();
    let targets_key = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap();
    let targets_key_1 = PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap();
    let timestamp_key = PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519).unwrap();
    let timestamp_key_1 = PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519).unwrap();

    let mut keys = HashMap::new();
    keys.insert("root", [root_key_0, root_key_1]);
    keys.insert("snapshot", [snapshot_key, snapshot_key_1]);
    keys.insert("targets", [targets_key, targets_key_1]);
    keys.insert("timestamp", [timestamp_key, timestamp_key_1]);
    keys
}

// TODO correct return type, something that awaits this.
// when you add a return type, you will have to deal with some ? vs unwrap shit.
fn generate_repos(dir: &str, consistent_snapshot: bool) -> tuf::Result<()> {
    // Create initial repo.
    println!("generate_repos: {}", consistent_snapshot);
    let keys = test_keys();
    let dir0 = Path::new(dir).join("0");
    let repo = FileSystemRepositoryBuilder::new(dir0)
        .metadata_prefix(Path::new("repository"))
        .targets_prefix(Path::new("repository").join("targets"))
        .build()?;

    // TODO assuming this should be signed?
    let root = RootMetadataBuilder::new()
        .root_key(keys.get("root").unwrap()[0].public().clone())
        .snapshot_key(keys.get("snapshot").unwrap()[0].public().clone())
        .targets_key(keys.get("targets").unwrap()[0].public().clone())
        .timestamp_key(keys.get("timestamp").unwrap()[0].public().clone())
        .consistent_snapshot(consistent_snapshot)
        .signed::<Json>(&keys.get("root").unwrap()[0])?;

    let root_path = MetadataPath::from_role(&Role::Root);

    let targets_path = MetadataPath::from_role(&Role::Targets);
    // TODO do I need to sign stuff?
    // targets.add_signature(&KEYS[1])?;
    let target_data: &[u8] = b"0";
    let target_path = TargetPath::new("0".into())?;

    let targets = TargetsMetadataBuilder::new()
        .insert_target_from_reader(
            // TODO paramatrize
            VirtualTargetPath::new("0".into())?,
            target_data,
            &[HashAlgorithm::Sha256],
        )?
        .signed::<Json>(&keys.get("targets").unwrap()[0])?;

    let targets_path = &MetadataPath::new("targets")?;

    let snapshot_path = MetadataPath::from_role(&Role::Snapshot);
    let snapshot = SnapshotMetadataBuilder::new()
        .insert_metadata(&targets, &[HashAlgorithm::Sha256])?
        .signed::<Json>(&keys.get("snapshot").unwrap()[0])?;

    let timestamp_path = MetadataPath::from_role(&Role::Timestamp);
    let timestamp = TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])?
        .signed::<Json>(&keys.get("timestamp").unwrap()[0])?;

    block_on(async {
        repo.store_metadata(&root_path, &MetadataVersion::Number(1), &root)
            .await;
        repo.store_metadata(&root_path, &MetadataVersion::None, &root)
            .await;
        repo.store_target(target_data, &target_path).await;
        repo.store_metadata(&targets_path, &MetadataVersion::None, &targets)
            .await;
        repo.store_metadata(&snapshot_path, &MetadataVersion::None, &snapshot)
            .await;
        repo.store_metadata(&timestamp_path, &MetadataVersion::None, &timestamp)
            .await;
    });
    Ok(())
}

// TODO delete this if we don't move main to separate file
pub fn generate(dir: &str, consistent_snapshot: bool) -> Result<()> {
    // TODO create all the necessary files.

    generate_repos(dir, consistent_snapshot)

    //f.write_all(b"golden metadata\n")?;
}

// TODO move to a separate file or nah?
fn main() {
    // TODO figure out how to pass in a directory or make a sane assumption.
    //f.write_all(b"golden metadata\n").unwrap();
    generate("consistent-snapshot-true", true).unwrap();
    generate("consistent-snapshot-false", false).unwrap();
}
