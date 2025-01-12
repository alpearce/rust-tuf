use chrono::offset::Utc;
use chrono::prelude::*;
use serde_derive::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};

use crate::crypto;
use crate::error::Error;
use crate::metadata::{self, Metadata};
use crate::Result;

const SPEC_VERSION: &str = "1.0";

fn parse_datetime(ts: &str) -> Result<DateTime<Utc>> {
    Utc.datetime_from_str(ts, "%FT%TZ")
        .map_err(|e| Error::Encoding(format!("Can't parse DateTime: {:?}", e)))
}

fn format_datetime(ts: &DateTime<Utc>) -> String {
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        ts.year(),
        ts.month(),
        ts.day(),
        ts.hour(),
        ts.minute(),
        ts.second()
    )
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RootMetadata {
    #[serde(rename = "_type")]
    typ: metadata::Role,
    spec_version: String,
    version: u32,
    consistent_snapshot: bool,
    expires: String,
    #[serde(deserialize_with = "deserialize_reject_duplicates::deserialize")]
    keys: BTreeMap<crypto::KeyId, crypto::PublicKey>,
    roles: RoleDefinitions,
}

impl RootMetadata {
    pub fn from(meta: &metadata::RootMetadata) -> Result<Self> {
        Ok(RootMetadata {
            typ: metadata::Role::Root,
            spec_version: SPEC_VERSION.to_string(),
            version: meta.version(),
            expires: format_datetime(&meta.expires()),
            consistent_snapshot: meta.consistent_snapshot(),
            keys: meta
                .keys()
                .iter()
                .map(|(id, key)| (id.clone(), key.clone()))
                .collect(),
            roles: RoleDefinitions {
                root: meta.root().clone(),
                snapshot: meta.snapshot().clone(),
                targets: meta.targets().clone(),
                timestamp: meta.timestamp().clone(),
            },
        })
    }

    pub fn try_into(self) -> Result<metadata::RootMetadata> {
        if self.typ != metadata::Role::Root {
            return Err(Error::Encoding(format!(
                "Attempted to decode root metdata labeled as {:?}",
                self.typ
            )));
        }

        if self.spec_version != SPEC_VERSION {
            return Err(Error::Encoding(format!(
                "Unknown spec version {}",
                self.spec_version
            )));
        }

        metadata::RootMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.consistent_snapshot,
            self.keys.into_iter().collect(),
            self.roles.root,
            self.roles.snapshot,
            self.roles.targets,
            self.roles.timestamp,
        )
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RoleDefinitions {
    root: metadata::RoleDefinition,
    snapshot: metadata::RoleDefinition,
    targets: metadata::RoleDefinition,
    timestamp: metadata::RoleDefinition,
}

#[derive(Serialize, Deserialize)]
pub struct RoleDefinition {
    threshold: u32,
    #[serde(rename = "keyids")]
    key_ids: Vec<crypto::KeyId>,
}

impl RoleDefinition {
    pub fn from(role: &metadata::RoleDefinition) -> Result<Self> {
        let key_ids = role
            .key_ids()
            .iter()
            .cloned()
            .collect::<Vec<crypto::KeyId>>();

        Ok(RoleDefinition {
            threshold: role.threshold(),
            key_ids,
        })
    }

    pub fn try_into(self) -> Result<metadata::RoleDefinition> {
        let vec_len = self.key_ids.len();
        if vec_len < 1 {
            return Err(Error::Encoding(
                "Role defined with no assoiciated key IDs.".into(),
            ));
        }

        let mut seen = HashSet::new();
        let mut dupes = 0;
        for key_id in self.key_ids.iter() {
            if !seen.insert(key_id) {
                dupes += 1;
            }
        }

        if dupes != 0 {
            return Err(Error::Encoding(format!(
                "Found {} duplicate key IDs.",
                dupes
            )));
        }

        Ok(metadata::RoleDefinition::new(self.threshold, self.key_ids)?)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TimestampMetadata {
    #[serde(rename = "_type")]
    typ: metadata::Role,
    spec_version: String,
    version: u32,
    expires: String,
    meta: TimestampMeta,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TimestampMeta {
    #[serde(rename = "snapshot.json")]
    snapshot: metadata::MetadataDescription,
}

impl TimestampMetadata {
    pub fn from(metadata: &metadata::TimestampMetadata) -> Result<Self> {
        Ok(TimestampMetadata {
            typ: metadata::Role::Timestamp,
            spec_version: SPEC_VERSION.to_string(),
            version: metadata.version(),
            expires: format_datetime(metadata.expires()),
            meta: TimestampMeta {
                snapshot: metadata.snapshot().clone(),
            },
        })
    }

    pub fn try_into(self) -> Result<metadata::TimestampMetadata> {
        if self.typ != metadata::Role::Timestamp {
            return Err(Error::Encoding(format!(
                "Attempted to decode timestamp metdata labeled as {:?}",
                self.typ
            )));
        }

        if self.spec_version != SPEC_VERSION {
            return Err(Error::Encoding(format!(
                "Unknown spec version {}",
                self.spec_version
            )));
        }

        metadata::TimestampMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.meta.snapshot,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct SnapshotMetadata {
    #[serde(rename = "_type")]
    typ: metadata::Role,
    spec_version: String,
    version: u32,
    expires: String,
    #[serde(deserialize_with = "deserialize_reject_duplicates::deserialize")]
    meta: BTreeMap<String, metadata::MetadataDescription>,
}

impl SnapshotMetadata {
    pub fn from(metadata: &metadata::SnapshotMetadata) -> Result<Self> {
        Ok(SnapshotMetadata {
            typ: metadata::Role::Snapshot,
            spec_version: SPEC_VERSION.to_string(),
            version: metadata.version(),
            expires: format_datetime(&metadata.expires()),
            meta: metadata
                .meta()
                .iter()
                .map(|(p, d)| (format!("{}.json", p), d.clone()))
                .collect(),
        })
    }

    pub fn try_into(self) -> Result<metadata::SnapshotMetadata> {
        if self.typ != metadata::Role::Snapshot {
            return Err(Error::Encoding(format!(
                "Attempted to decode snapshot metdata labeled as {:?}",
                self.typ
            )));
        }

        if self.spec_version != SPEC_VERSION {
            return Err(Error::Encoding(format!(
                "Unknown spec version {}",
                self.spec_version
            )));
        }

        metadata::SnapshotMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.meta
                .into_iter()
                .map(|(p, d)| {
                    if !p.ends_with(".json") {
                        return Err(Error::Encoding(format!(
                            "Metadata does not end with .json: {}",
                            p
                        )));
                    }

                    let s = p.split_at(p.len() - ".json".len()).0;
                    let p = metadata::MetadataPath::new(s)?;

                    Ok((p, d))
                })
                .collect::<Result<_>>()?,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct TargetsMetadata {
    #[serde(rename = "_type")]
    typ: metadata::Role,
    spec_version: String,
    version: u32,
    expires: String,
    targets: BTreeMap<metadata::VirtualTargetPath, metadata::TargetDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delegations: Option<metadata::Delegations>,
}

impl TargetsMetadata {
    pub fn from(metadata: &metadata::TargetsMetadata) -> Result<Self> {
        Ok(TargetsMetadata {
            typ: metadata::Role::Targets,
            spec_version: SPEC_VERSION.to_string(),
            version: metadata.version(),
            expires: format_datetime(&metadata.expires()),
            targets: metadata
                .targets()
                .iter()
                .map(|(p, d)| (p.clone(), d.clone()))
                .collect(),
            delegations: metadata.delegations().cloned(),
        })
    }

    pub fn try_into(self) -> Result<metadata::TargetsMetadata> {
        if self.typ != metadata::Role::Targets {
            return Err(Error::Encoding(format!(
                "Attempted to decode targets metdata labeled as {:?}",
                self.typ
            )));
        }

        if self.spec_version != SPEC_VERSION {
            return Err(Error::Encoding(format!(
                "Unknown spec version {}",
                self.spec_version
            )));
        }

        metadata::TargetsMetadata::new(
            self.version,
            parse_datetime(&self.expires)?,
            self.targets.into_iter().collect(),
            self.delegations,
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKey {
    keytype: crypto::KeyType,
    scheme: crypto::SignatureScheme,
    #[serde(skip_serializing_if = "Option::is_none")]
    keyid_hash_algorithms: Option<Vec<String>>,
    keyval: PublicKeyValue,
}

impl PublicKey {
    pub fn new(
        keytype: crypto::KeyType,
        scheme: crypto::SignatureScheme,
        keyid_hash_algorithms: Option<Vec<String>>,
        public_key: String,
    ) -> Self {
        PublicKey {
            keytype,
            scheme,
            keyid_hash_algorithms,
            keyval: PublicKeyValue { public: public_key },
        }
    }

    pub fn public_key(&self) -> &str {
        &self.keyval.public
    }

    pub fn scheme(&self) -> &crypto::SignatureScheme {
        &self.scheme
    }

    pub fn keytype(&self) -> &crypto::KeyType {
        &self.keytype
    }

    pub fn keyid_hash_algorithms(&self) -> &Option<Vec<String>> {
        &self.keyid_hash_algorithms
    }
}

#[derive(Serialize, Deserialize)]
pub struct PublicKeyValue {
    public: String,
}

#[derive(Serialize, Deserialize)]
pub struct Delegation {
    role: metadata::MetadataPath,
    terminating: bool,
    threshold: u32,
    #[serde(rename = "keyids")]
    key_ids: Vec<crypto::KeyId>,
    paths: Vec<metadata::VirtualTargetPath>,
}

impl Delegation {
    pub fn from(meta: &metadata::Delegation) -> Self {
        let mut paths = meta
            .paths()
            .iter()
            .cloned()
            .collect::<Vec<metadata::VirtualTargetPath>>();
        paths.sort();
        let mut key_ids = meta
            .key_ids()
            .iter()
            .cloned()
            .collect::<Vec<crypto::KeyId>>();
        key_ids.sort();

        Delegation {
            role: meta.role().clone(),
            terminating: meta.terminating(),
            threshold: meta.threshold(),
            key_ids,
            paths,
        }
    }

    pub fn try_into(self) -> Result<metadata::Delegation> {
        let paths = self
            .paths
            .iter()
            .cloned()
            .collect::<HashSet<metadata::VirtualTargetPath>>();
        if paths.len() != self.paths.len() {
            return Err(Error::Encoding("Non-unique delegation paths.".into()));
        }

        let key_ids = self
            .key_ids
            .iter()
            .cloned()
            .collect::<HashSet<crypto::KeyId>>();
        if key_ids.len() != self.key_ids.len() {
            return Err(Error::Encoding("Non-unique delegation key IDs.".into()));
        }

        metadata::Delegation::new(self.role, self.terminating, self.threshold, key_ids, paths)
    }
}

#[derive(Serialize, Deserialize)]
pub struct Delegations {
    #[serde(deserialize_with = "deserialize_reject_duplicates::deserialize")]
    keys: BTreeMap<crypto::KeyId, crypto::PublicKey>,
    roles: Vec<metadata::Delegation>,
}

impl Delegations {
    pub fn from(delegations: &metadata::Delegations) -> Delegations {
        Delegations {
            keys: delegations
                .keys()
                .iter()
                .map(|(id, key)| (id.clone(), key.clone()))
                .collect(),
            roles: delegations.roles().clone(),
        }
    }

    pub fn try_into(self) -> Result<metadata::Delegations> {
        metadata::Delegations::new(self.keys.into_iter().collect(), self.roles)
    }
}

#[derive(Serialize, Deserialize)]
pub struct TargetDescription {
    length: u64,
    hashes: BTreeMap<crypto::HashAlgorithm, crypto::HashValue>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custom: Option<BTreeMap<String, serde_json::Value>>,
}

impl TargetDescription {
    pub fn from(description: &metadata::TargetDescription) -> TargetDescription {
        TargetDescription {
            length: description.length(),
            hashes: description
                .hashes()
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
            custom: description
                .custom()
                .map(|custom| custom.iter().map(|(k, v)| (k.clone(), v.clone())).collect()),
        }
    }

    pub fn try_into(self) -> Result<metadata::TargetDescription> {
        metadata::TargetDescription::new(
            self.length,
            self.hashes.into_iter().collect(),
            self.custom.map(|custom| custom.into_iter().collect()),
        )
    }
}

#[derive(Deserialize)]
pub struct MetadataDescription {
    version: u32,
    length: usize,
    hashes: BTreeMap<crypto::HashAlgorithm, crypto::HashValue>,
}

impl MetadataDescription {
    pub fn try_into(self) -> Result<metadata::MetadataDescription> {
        metadata::MetadataDescription::new(
            self.version,
            self.length,
            self.hashes.into_iter().collect(),
        )
    }
}

/// Custom deserialize to reject duplicate keys.
mod deserialize_reject_duplicates {
    use serde::de::{Deserialize, Deserializer, Error, MapAccess, Visitor};
    use std::collections::BTreeMap;
    use std::fmt;
    use std::marker::PhantomData;
    use std::result::Result;

    pub fn deserialize<'de, K, V, D>(deserializer: D) -> Result<BTreeMap<K, V>, D::Error>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
        D: Deserializer<'de>,
    {
        struct BTreeVisitor<K, V> {
            marker: PhantomData<(K, V)>,
        };

        impl<'de, K, V> Visitor<'de> for BTreeVisitor<K, V>
        where
            K: Deserialize<'de> + Ord,
            V: Deserialize<'de>,
        {
            type Value = BTreeMap<K, V>;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("map")
            }

            fn visit_map<M>(self, mut access: M) -> std::result::Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut map = BTreeMap::new();
                while let Some((key, value)) = access.next_entry()? {
                    if map.insert(key, value).is_some() {
                        return Err(M::Error::custom("Cannot have duplicate keys"));
                    }
                }
                Ok(map)
            }
        }

        deserializer.deserialize_map(BTreeVisitor {
            marker: PhantomData,
        })
    }
}
