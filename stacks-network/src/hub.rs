use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use stacks_network_types::{Announcement, ContentId, NetworkObject};

pub const DEFAULT_OBJECT_CACHE_BYTES: usize = 32 * 1024 * 1024;
pub const MAX_PROVIDERS_PER_OBJECT: usize = 8;

/// Consensus/domain validation injected by the embedding node. Transport code
/// never guesses Stacks IDs from generic hashes.
pub trait NetworkObjectValidator: Send + Sync {
    fn validate_announcement(&self, announcement: &Announcement) -> Result<(), String>;
    fn validate_object(&self, object: &NetworkObject) -> Result<(), String>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectAdmission {
    New,
    AlreadyHave,
}

pub struct NetworkHub {
    validator: Arc<dyn NetworkObjectValidator>,
    objects: HashMap<ContentId, NetworkObject>,
    object_order: VecDeque<ContentId>,
    object_bytes: usize,
    max_object_bytes: usize,
    announcements: HashSet<ContentId>,
    announcement_order: VecDeque<ContentId>,
    providers: HashMap<ContentId, Vec<PeerId>>,
    in_validation: HashMap<ContentId, Instant>,
}

impl NetworkHub {
    pub fn new(validator: Arc<dyn NetworkObjectValidator>, max_object_bytes: usize) -> Self {
        Self {
            validator,
            objects: HashMap::new(),
            object_order: VecDeque::new(),
            object_bytes: 0,
            max_object_bytes: max_object_bytes.max(1),
            announcements: HashSet::new(),
            announcement_order: VecDeque::new(),
            providers: HashMap::new(),
            in_validation: HashMap::new(),
        }
    }

    pub fn admit_announcement(
        &mut self,
        announcement: &Announcement,
        provider: PeerId,
    ) -> Result<ObjectAdmission, String> {
        self.validator.validate_announcement(announcement)?;
        let announcement_id = announcement_id(announcement);
        let is_new = self.announcements.insert(announcement_id);
        if is_new {
            self.announcement_order.push_back(announcement_id);
            while self.announcement_order.len() > 8192 {
                if let Some(expired) = self.announcement_order.pop_front() {
                    self.announcements.remove(&expired);
                }
            }
        }
        let providers = self.providers.entry(announcement.content_id).or_default();
        if !providers.contains(&provider) && providers.len() < MAX_PROVIDERS_PER_OBJECT {
            providers.push(provider);
        }
        Ok(
            if is_new
                && !self.objects.contains_key(&announcement.content_id)
                && !self.in_validation.contains_key(&announcement.content_id)
            {
                ObjectAdmission::New
            } else {
                ObjectAdmission::AlreadyHave
            },
        )
    }

    /// Validate canonical announcement metadata without mutating provider or
    /// deduplication state. Used to make compound local publication atomic.
    pub fn validate_announcement(&self, announcement: &Announcement) -> Result<(), String> {
        self.validator.validate_announcement(announcement)
    }

    /// Commit an object already accepted by the local domain/chainstate. Only
    /// committed objects are served to remote fetchers.
    pub fn admit_object(&mut self, object: NetworkObject) -> Result<ObjectAdmission, String> {
        self.validator.validate_object(&object)?;
        self.in_validation.remove(&object.content_id);
        if self.objects.contains_key(&object.content_id) {
            return Ok(ObjectAdmission::AlreadyHave);
        }
        if object.bytes.len() > self.max_object_bytes {
            return Err("object exceeds the entire bounded cache".to_owned());
        }
        self.object_bytes = self.object_bytes.saturating_add(object.bytes.len());
        self.object_order.push_back(object.content_id);
        self.objects.insert(object.content_id, object);
        while self.object_bytes > self.max_object_bytes {
            let Some(expired) = self.object_order.pop_front() else {
                break;
            };
            if let Some(object) = self.objects.remove(&expired) {
                self.object_bytes = self.object_bytes.saturating_sub(object.bytes.len());
            }
        }
        Ok(ObjectAdmission::New)
    }

    /// Reserve a structurally valid remote object for contextual validation
    /// without making its bytes available to other peers.
    pub fn begin_validation(&mut self, object: &NetworkObject) -> Result<ObjectAdmission, String> {
        self.validator.validate_object(object)?;
        if self.objects.contains_key(&object.content_id)
            || self.in_validation.contains_key(&object.content_id)
        {
            return Ok(ObjectAdmission::AlreadyHave);
        }
        self.in_validation.insert(object.content_id, Instant::now());
        Ok(ObjectAdmission::New)
    }

    pub fn reject_validation(&mut self, content_id: &ContentId) {
        self.in_validation.remove(content_id);
    }

    pub fn expire_validations(&mut self, max_age: Duration) -> usize {
        let cutoff = Instant::now() - max_age;
        let before = self.in_validation.len();
        self.in_validation
            .retain(|_, admitted_at| *admitted_at >= cutoff);
        before.saturating_sub(self.in_validation.len())
    }

    pub fn get(&self, content_id: &ContentId) -> Option<&NetworkObject> {
        self.objects.get(content_id)
    }

    pub fn providers(&self, content_id: &ContentId) -> &[PeerId] {
        self.providers
            .get(content_id)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub fn needs_object(&self, content_id: &ContentId) -> bool {
        !self.objects.contains_key(content_id) && !self.in_validation.contains_key(content_id)
    }

    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    pub fn object_bytes(&self) -> usize {
        self.object_bytes
    }
}

pub fn announcement_id(announcement: &Announcement) -> ContentId {
    let mut transcript = Vec::with_capacity(announcement.canonical_metadata.len() + 40);
    transcript.extend_from_slice(&(announcement.kind as u8).to_be_bytes());
    transcript.extend_from_slice(announcement.content_id.as_bytes());
    transcript.extend_from_slice(&(announcement.canonical_metadata.len() as u64).to_be_bytes());
    transcript.extend_from_slice(&announcement.canonical_metadata);
    ContentId::from_domain_bytes(b"STACKS_OBJECT_ANNOUNCEMENT_V1", &transcript)
}

#[cfg(test)]
mod tests {
    use super::*;
    use stacks_network_types::ObjectKind;

    struct FixtureValidator;

    impl NetworkObjectValidator for FixtureValidator {
        fn validate_announcement(&self, announcement: &Announcement) -> Result<(), String> {
            if announcement.canonical_metadata == b"valid" {
                Ok(())
            } else {
                Err("bad metadata".to_owned())
            }
        }

        fn validate_object(&self, object: &NetworkObject) -> Result<(), String> {
            let expected = ContentId::from_domain_bytes(b"fixture", &object.bytes);
            (expected == object.content_id)
                .then_some(())
                .ok_or_else(|| "content mismatch".to_owned())
        }
    }

    #[test]
    fn metadata_variants_cannot_poison_content_and_cache_is_bounded() {
        let mut hub = NetworkHub::new(Arc::new(FixtureValidator), 6);
        let bytes = b"abc".to_vec();
        let id = ContentId::from_domain_bytes(b"fixture", &bytes);
        let announcement = Announcement {
            kind: ObjectKind::NakamotoBlock,
            content_id: id,
            canonical_metadata: b"valid".to_vec(),
        };
        let first_provider = PeerId::random();
        let second_provider = PeerId::random();
        assert_eq!(
            hub.admit_announcement(&announcement, first_provider)
                .unwrap(),
            ObjectAdmission::New
        );
        assert_eq!(
            hub.admit_announcement(&announcement, second_provider)
                .unwrap(),
            ObjectAdmission::AlreadyHave
        );
        assert_eq!(hub.providers(&id), &[first_provider, second_provider]);
        let mut poisoned = announcement.clone();
        poisoned.canonical_metadata = b"variant".to_vec();
        assert!(hub.admit_announcement(&poisoned, PeerId::random()).is_err());
        assert_eq!(
            hub.admit_object(NetworkObject {
                kind: ObjectKind::NakamotoBlock,
                content_id: id,
                bytes,
            })
            .unwrap(),
            ObjectAdmission::New
        );
        for value in [b"def".to_vec(), b"ghi".to_vec()] {
            hub.admit_object(NetworkObject {
                kind: ObjectKind::NakamotoBlock,
                content_id: ContentId::from_domain_bytes(b"fixture", &value),
                bytes: value,
            })
            .unwrap();
        }
        assert_eq!(hub.object_count(), 2);
        assert_eq!(hub.object_bytes(), 6);
    }

    #[test]
    fn remote_objects_are_not_served_before_contextual_acceptance() {
        let mut hub = NetworkHub::new(Arc::new(FixtureValidator), 1024);
        let bytes = b"candidate".to_vec();
        let content_id = ContentId::from_domain_bytes(b"fixture", &bytes);
        let object = NetworkObject {
            kind: ObjectKind::NakamotoBlock,
            content_id,
            bytes,
        };

        assert_eq!(hub.begin_validation(&object).unwrap(), ObjectAdmission::New);
        assert!(hub.get(&content_id).is_none());
        assert_eq!(
            hub.begin_validation(&object).unwrap(),
            ObjectAdmission::AlreadyHave
        );

        hub.reject_validation(&content_id);
        assert_eq!(hub.begin_validation(&object).unwrap(), ObjectAdmission::New);
        assert!(hub.get(&content_id).is_none());

        assert_eq!(
            hub.admit_object(object.clone()).unwrap(),
            ObjectAdmission::New
        );
        assert_eq!(hub.get(&content_id), Some(&object));
        assert_eq!(
            hub.begin_validation(&object).unwrap(),
            ObjectAdmission::AlreadyHave
        );
    }
}
