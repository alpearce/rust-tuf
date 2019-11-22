use data_encoding::HEXLOWER;
use futures_executor::block_on;
use serde_derive::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;
use std::process::Command;
use tuf::crypto::{HashAlgorithm, KeyType, PrivateKey, SignatureScheme};
use tuf::interchange::Json;
use tuf::metadata::{
    MetadataPath, MetadataVersion, Role, RootMetadataBuilder, SnapshotMetadataBuilder, TargetPath,
    TargetsMetadataBuilder, TimestampMetadataBuilder, VirtualTargetPath,
};
use tuf::repository::{FileSystemRepository, FileSystemRepositoryBuilder, Repository};

// TODO parametrize this better/find it within the build?
const KEYS_PATH: &str = "./keys.json";

// These structs and functions are necessary to parse keys.json, which contains the keys
// used by go-tuf to generate the equivalent metadata. We use the same keys to facilitate
// compatibility testing.

#[derive(Clone, Deserialize)]
struct KeyValue {
    public: String,
    private: String,
}

#[derive(Clone, Deserialize)]
struct TestKeyPair {
    keytype: KeyType,
    scheme: SignatureScheme,
    keyid_hash_algorithms: Option<Vec<String>>,
    keyval: KeyValue,
}

impl TestKeyPair {
    fn to_private_key(&self) -> PrivateKey {
        let priv_bytes = HEXLOWER.decode(self.keyval.private.as_bytes()).unwrap();
        let pk = PrivateKey::from_ed25519(&priv_bytes[..]).unwrap();
        return pk;
    }
}

#[derive(Deserialize)]
struct TestKeys {
    root: Vec<Vec<TestKeyPair>>,
    targets: Vec<Vec<TestKeyPair>>,
    snapshot: Vec<Vec<TestKeyPair>>,
    timestamp: Vec<Vec<TestKeyPair>>,
}

fn init_json_keys(path: &str) -> TestKeys {
    let mut f = File::open(path).expect("failed to open keys file");
    let mut contents = String::new();
    f.read_to_string(&mut contents)
        .expect("failed to read keys");
    let keys: TestKeys = serde_json::from_str(&contents).expect("serde failed");
    return keys;
}

// Map each role to its current key.
type RoleKeys = HashMap<&'static str, PrivateKey>;

fn init_role_keys(json_keys: &TestKeys) -> RoleKeys {
    let mut keys = HashMap::new();
    keys.insert("root", json_keys.root[0][0].to_private_key());
    keys.insert("snapshot", json_keys.snapshot[0][0].to_private_key());
    keys.insert("targets", json_keys.targets[0][0].to_private_key());
    keys.insert("timestamp", json_keys.timestamp[0][0].to_private_key());
    keys
}

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

// updates the root metadata. If root_signer is Some, use that to sign the
// metadata, otherwise use keys["root"].
async fn update_root(
    repo: &FileSystemRepository<Json>,
    keys: &RoleKeys,
    root_signer: Option<&PrivateKey>,
    version: u32,
    consistent_snapshot: bool,
) {
    let signer = match root_signer {
        Some(k) => k,
        None => keys.get("root").unwrap(),
    };

    let root = RootMetadataBuilder::new()
        .root_key(keys.get("root").unwrap().public().clone())
        .snapshot_key(keys.get("snapshot").unwrap().public().clone())
        .targets_key(keys.get("targets").unwrap().public().clone())
        .timestamp_key(keys.get("timestamp").unwrap().public().clone())
        .consistent_snapshot(consistent_snapshot)
        .signed::<Json>(signer)
        .unwrap();

    let root_path = MetadataPath::from_role(&Role::Root);
    repo.store_metadata(&root_path, &MetadataVersion::Number(version), &root)
        .await
        .unwrap();
    repo.store_metadata(&root_path, &MetadataVersion::None, &root)
        .await
        .unwrap();
}

// adds a target and updates the non-root metadata files.
async fn add_target(
    repo: &FileSystemRepository<Json>,
    keys: &RoleKeys,
    step: u8,
    consistent_snapshot: bool,
) {
    let targets_path = MetadataPath::from_role(&Role::Targets);
    let step_str = format!("{}", step);
    let target_data: &[u8] = step_str.as_bytes();

    let targets = TargetsMetadataBuilder::new()
        .insert_target_from_reader(
            VirtualTargetPath::new(step.to_string().into()).unwrap(),
            target_data,
            &[HashAlgorithm::Sha256],
        )
        .unwrap()
        .signed::<Json>(&keys.get("targets").unwrap())
        .unwrap();

    let hash = targets
        .as_ref()
        .targets()
        .get(&VirtualTargetPath::new(step.to_string().into()).unwrap())
        .unwrap()
        .hashes()
        .get(&HashAlgorithm::Sha256)
        .unwrap();

    let target_str = if consistent_snapshot {
        format!("{}.{}", hash, step.to_string())
    } else {
        step.to_string()
    };
    let target_path = TargetPath::new(target_str.into()).unwrap();
    repo.store_target(target_data, &target_path).await.unwrap();

    let version = if consistent_snapshot {
        MetadataVersion::Number((step + 1).into())
    } else {
        MetadataVersion::None
    };

    repo.store_metadata(&targets_path, &version, &targets)
        .await
        .unwrap();

    let snapshot_path = MetadataPath::from_role(&Role::Snapshot);
    let snapshot = SnapshotMetadataBuilder::new()
        .insert_metadata(&targets, &[HashAlgorithm::Sha256])
        .unwrap()
        .signed::<Json>(&keys.get("snapshot").unwrap())
        .unwrap();

    repo.store_metadata(&snapshot_path, &version, &snapshot)
        .await
        .unwrap();

    let timestamp_path = MetadataPath::from_role(&Role::Timestamp);
    let timestamp = TimestampMetadataBuilder::from_snapshot(&snapshot, &[HashAlgorithm::Sha256])
        .unwrap()
        .signed::<Json>(&keys.get("timestamp").unwrap())
        .unwrap();

    // Timestamp doesn't require a version even in consistent_snapshot.
    repo.store_metadata(&timestamp_path, &MetadataVersion::None, &timestamp)
        .await
        .unwrap();
}

async fn generate_repos(dir: &str, consistent_snapshot: bool) -> tuf::Result<()> {
    // Create initial repo.
    // TODO: @erickt, this impl is very tied to the json keys file. Do we need it to be more flexible?
    let json_keys = init_json_keys(KEYS_PATH);
    let mut keys = init_role_keys(&json_keys);
    let dir0 = Path::new(dir).join("0");
    let repo = FileSystemRepositoryBuilder::new(dir0)
        .metadata_prefix(Path::new("repository"))
        .targets_prefix(Path::new("repository").join("targets"))
        .build()?;

    update_root(&repo, &keys, None, 1, consistent_snapshot).await;
    add_target(&repo, &keys, 0, consistent_snapshot).await;

    let mut i: u8 = 1;
    let rotations = vec![
        Some(Role::Root),
        Some(Role::Targets),
        Some(Role::Snapshot),
        Some(Role::Timestamp),
        None,
    ];
    for r in rotations.iter() {
        // Initialize new repo and copy the files from the previous step.
        let dir_i = Path::new(dir).join(i.to_string());
        let repo = FileSystemRepositoryBuilder::new(dir_i)
            .metadata_prefix(Path::new("repository"))
            .targets_prefix(Path::new("repository").join("targets"))
            .build()
            .unwrap();
        copy_repo(dir, i);

        let root_signer: Option<PrivateKey> = match r {
            Some(Role::Root) => keys.insert("root", json_keys.root[1][0].to_private_key()),
            Some(Role::Targets) => {
                keys.insert("targets", json_keys.targets[1][0].to_private_key());
                None
            }
            Some(Role::Snapshot) => {
                keys.insert("snapshot", json_keys.snapshot[1][0].to_private_key());
                None
            }
            Some(Role::Timestamp) => {
                keys.insert("timestamp", json_keys.timestamp[1][0].to_private_key());
                None
            }
            None => None,
        };
        update_root(
            &repo,
            &keys,
            root_signer.as_ref(),
            (i + 1).into(),
            consistent_snapshot,
        )
        .await;
        add_target(&repo, &keys, i, consistent_snapshot).await;
        i = i + 1;
    }
    Ok(())
}

fn main() {
    block_on(async {
        generate_repos("consistent-snapshot-true", true)
            .await
            .unwrap();
        generate_repos("consistent-snapshot-false", false)
            .await
            .unwrap();
    })
}
