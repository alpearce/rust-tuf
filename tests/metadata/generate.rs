use std::fs::File;
//use std::io::prelude::*;
use std::collections::HashMap;
use std::path::Path;
//use tuf::crypto::{HashAlgorithm, KeyId, PrivateKey, SignatureScheme};
//use serde_json::{Result, Value};
use futures_executor::block_on;
use std::process::Command;
use tuf::crypto::{HashAlgorithm, PrivateKey, SignatureScheme};
use tuf::interchange::Json;
use tuf::metadata::{
    Metadata, MetadataPath, MetadataVersion, Role, RootMetadataBuilder, SignedMetadata,
    SnapshotMetadataBuilder, TargetPath, TargetsMetadataBuilder, TimestampMetadataBuilder,
    VirtualTargetPath,
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

// TODO: Read the keys in from the json file copied from the Go repo?
// or just regenerate them in pk8?
/*fn keys_from_json(path: &str) -> serde_json::Result<()> {
    let f = File::open(path).expect("failed to open keys file");
    let mut contents = String::new();
    f.read_to_string(&mut contents).expect("failed to read keys");
    let keys : serde_json::Value = serde_json::from_str(contents).expect("serde failed");
}*/

// Maps each role to a key.
type test_keys = HashMap<&'static str, PrivateKey>;

fn copy_repo(dir: &str, step: u8) {
    let src = Path::new(dir)
        .join((step - 1).to_string())
        .join("repository");
    let dst = Path::new(dir).join(step.to_string());
    Command::new("cp")
        .arg("-r")
        .arg(src.to_str().unwrap())
        .arg(dst.to_str().unwrap())
        .spawn()
        .expect("cp failed");
}

fn init_test_keys() -> test_keys {
    let mut keys = HashMap::new();
    keys.insert(
        "root",
        PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap(),
    );
    keys.insert(
        "snapshot",
        PrivateKey::from_pkcs8(ED25519_2_PK8, SignatureScheme::Ed25519).unwrap(),
    );
    keys.insert(
        "targets",
        PrivateKey::from_pkcs8(ED25519_3_PK8, SignatureScheme::Ed25519).unwrap(),
    );
    keys.insert(
        "timestamp",
        PrivateKey::from_pkcs8(ED25519_4_PK8, SignatureScheme::Ed25519).unwrap(),
    );
    keys
}

// TODO something better about the root signer
async fn update_root(
    repo: &FileSystemRepository<Json>,
    keys: &test_keys,
    root_signer: &PrivateKey,
    consistent_snapshot: bool,
) {
    let root = RootMetadataBuilder::new()
        .root_key(keys.get("root").unwrap().public().clone())
        .snapshot_key(keys.get("snapshot").unwrap().public().clone())
        .targets_key(keys.get("targets").unwrap().public().clone())
        .timestamp_key(keys.get("timestamp").unwrap().public().clone())
        .consistent_snapshot(consistent_snapshot)
        // Don't know if this needs to be a reference.
        .signed::<Json>(&root_signer)
        .unwrap();

    let root_path = MetadataPath::from_role(&Role::Root);
    repo.store_metadata(&root_path, &MetadataVersion::Number(1), &root)
        .await;
    repo.store_metadata(&root_path, &MetadataVersion::None, &root)
        .await;
}

async fn add_target(repo: &FileSystemRepository<Json>, keys: &test_keys, step: u8) {
    let targets_path = MetadataPath::from_role(&Role::Targets);
    let target_data: &[u8] = &[step];
    let target_path = TargetPath::new(step.to_string().into()).unwrap();

    repo.store_target(target_data, &target_path).await;

    let targets = TargetsMetadataBuilder::new()
        .insert_target_from_reader(
            VirtualTargetPath::new(step.to_string().into()).unwrap(),
            target_data,
            &[HashAlgorithm::Sha256],
        )
        .unwrap()
        .signed::<Json>(&keys.get("targets").unwrap())
        .unwrap();

    let targets_path = &MetadataPath::new("targets").unwrap();
    repo.store_metadata(&targets_path, &MetadataVersion::None, &targets)
        .await;

    let snapshot_path = MetadataPath::from_role(&Role::Snapshot);
    let snapshot = SnapshotMetadataBuilder::new()
        .insert_metadata(&targets, &[HashAlgorithm::Sha256])
        .unwrap()
        .signed::<Json>(&keys.get("snapshot").unwrap())
        .unwrap();

    let timestamp_path = MetadataPath::from_role(&Role::Timestamp);
    let timestamp = TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
        .unwrap()
        .signed::<Json>(&keys.get("timestamp").unwrap())
        .unwrap();
}

fn generate_repos(dir: &str, consistent_snapshot: bool) -> tuf::Result<()> {
    // Create initial repo.
    println!("generate_repos: {}", consistent_snapshot);
    let mut keys = init_test_keys();
    let dir0 = Path::new(dir).join("0");
    let repo = FileSystemRepositoryBuilder::new(dir0)
        .metadata_prefix(Path::new("repository"))
        .targets_prefix(Path::new("repository").join("targets"))
        .build()?;

    block_on(async {
        update_root(&repo, &keys, keys.get("root").unwrap(), consistent_snapshot).await;
        add_target(&repo, &keys, 0).await;
    });

    let mut i: u8 = 1;
    let roles = vec![Role::Root, Role::Targets, Role::Snapshot, Role::Timestamp];
    block_on(async {
        for r in roles.iter() {
            // Initialize new repo and copy the files from the previous step.
            let dir_i = Path::new(dir).join(i.to_string());
            let repo = FileSystemRepositoryBuilder::new(dir_i)
                .metadata_prefix(Path::new("repository"))
                .targets_prefix(Path::new("repository").join("targets"))
                .build()
                .unwrap();
            copy_repo(dir, i);

            // TODO  impl clone for keys, I gues???
            //let root_signer = keys.get("root").unwrap();
            //
            let root_signer =
                PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap();
            match r {
                // TODO figure out which keys to use
                Role::Root => keys.insert(
                    "root",
                    PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap(),
                ),
                Role::Targets => keys.insert(
                    "targets",
                    PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap(),
                ),
                Role::Snapshot => keys.insert(
                    "snapshot",
                    PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap(),
                ),
                Role::Timestamp => keys.insert(
                    "timestamp",
                    PrivateKey::from_pkcs8(ED25519_1_PK8, SignatureScheme::Ed25519).unwrap(),
                ),
            };
            update_root(&repo, &keys, &root_signer, consistent_snapshot).await;
            add_target(&repo, &keys, i).await;
            i = i + 1;
        }
    });
    // TODO add the final target.
    Ok(())
}

// TODO delete this if we don't move main to separate file
pub fn generate(dir: &str, consistent_snapshot: bool) -> Result<()> {
    generate_repos(dir, consistent_snapshot)
}

// TODO move to a separate file or nah?
fn main() {
    generate("consistent-snapshot-true", true).unwrap();
    generate("consistent-snapshot-false", false).unwrap();
}
