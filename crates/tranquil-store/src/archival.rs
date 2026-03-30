use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use crate::eventlog::{SEGMENT_FILE_EXTENSION, SegmentId, parse_segment_id, segment_path};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArchivalState {
    pub last_archived_segment: Option<SegmentId>,
}

impl ArchivalState {
    fn empty() -> Self {
        Self {
            last_archived_segment: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArchivalPassResult {
    pub segments_archived: u32,
    pub bytes_archived: u64,
}

pub trait ArchivalDestination: Send + Sync {
    fn store_segment(&self, segment_id: SegmentId, data: &[u8]) -> io::Result<()>;
}

pub struct LocalArchivalDestination {
    dest_dir: PathBuf,
}

impl LocalArchivalDestination {
    pub fn new(dest_dir: PathBuf) -> io::Result<Self> {
        std::fs::create_dir_all(&dest_dir)?;
        Ok(Self { dest_dir })
    }
}

impl ArchivalDestination for LocalArchivalDestination {
    fn store_segment(&self, segment_id: SegmentId, data: &[u8]) -> io::Result<()> {
        let dest_path = segment_path(&self.dest_dir, segment_id);
        let tmp_path = dest_path.with_extension(format!("{SEGMENT_FILE_EXTENSION}.tmp"));

        std::fs::write(&tmp_path, data)?;

        let f = std::fs::File::open(&tmp_path)?;
        f.sync_all()?;
        drop(f);

        std::fs::rename(&tmp_path, &dest_path)?;

        sync_dir(&self.dest_dir)?;

        Ok(())
    }
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    let d = std::fs::File::open(dir)?;
    d.sync_all()
}

fn list_segment_files(segments_dir: &Path) -> io::Result<Vec<SegmentId>> {
    let entries = match std::fs::read_dir(segments_dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };

    let mut ids: Vec<SegmentId> = entries
        .filter_map(|entry| parse_segment_id(&entry.ok()?.path()))
        .collect();
    ids.sort();
    Ok(ids)
}

pub struct ArchivalSidecar {
    path: PathBuf,
}

impl ArchivalSidecar {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }

    pub fn load(&self) -> io::Result<ArchivalState> {
        match std::fs::read(&self.path) {
            Ok(data) => serde_json::from_slice(&data)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(ArchivalState::empty()),
            Err(e) => Err(e),
        }
    }

    pub fn save(&self, state: &ArchivalState) -> io::Result<()> {
        let json =
            serde_json::to_vec(state).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &json)?;
        let f = std::fs::File::open(&tmp_path)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp_path, &self.path)?;

        self.path.parent().map(sync_dir).transpose()?;

        Ok(())
    }
}

pub struct ContinuousArchiver {
    segments_dir: PathBuf,
    sidecar: ArchivalSidecar,
    destination: Box<dyn ArchivalDestination>,
}

impl ContinuousArchiver {
    pub fn new(
        segments_dir: PathBuf,
        sidecar_path: PathBuf,
        destination: Box<dyn ArchivalDestination>,
    ) -> Self {
        Self {
            segments_dir,
            sidecar: ArchivalSidecar::new(sidecar_path),
            destination,
        }
    }

    pub fn run_pass(&self) -> io::Result<ArchivalPassResult> {
        let state = self.sidecar.load()?;

        let all_segments = list_segment_files(&self.segments_dir)?;

        let sealed_segments = match all_segments.len() {
            0 | 1 => Vec::new(),
            n => all_segments[..n - 1].to_vec(),
        };

        let new_segments: Vec<SegmentId> = match state.last_archived_segment {
            Some(last) => sealed_segments
                .into_iter()
                .filter(|&id| id > last)
                .collect(),
            None => sealed_segments,
        };

        if new_segments.is_empty() {
            debug!("no new sealed segments to archive");
            return Ok(ArchivalPassResult {
                segments_archived: 0,
                bytes_archived: 0,
            });
        }

        let mut segments_archived = 0u32;
        let mut bytes_archived = 0u64;

        let result = new_segments.iter().try_for_each(|&seg_id| {
            let path = segment_path(&self.segments_dir, seg_id);
            let data = std::fs::read(&path)?;
            let size = data.len() as u64;

            self.destination.store_segment(seg_id, &data)?;

            self.sidecar.save(&ArchivalState {
                last_archived_segment: Some(seg_id),
            })?;

            segments_archived = segments_archived.saturating_add(1);
            bytes_archived = bytes_archived.saturating_add(size);

            info!(
                segment_id = %seg_id,
                size_bytes = size,
                "archived sealed segment"
            );

            Ok::<(), io::Error>(())
        });

        match result {
            Ok(()) => {}
            Err(e) => {
                warn!(
                    segments_archived,
                    bytes_archived,
                    error = %e,
                    "archival pass interrupted after partial progress"
                );
                return Err(e);
            }
        }

        Ok(ArchivalPassResult {
            segments_archived,
            bytes_archived,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::{Arc, Mutex};

    type ArchivedSegments = Arc<Mutex<Vec<(SegmentId, Vec<u8>)>>>;

    #[derive(Clone)]
    struct CollectingDestination {
        stored: ArchivedSegments,
    }

    impl CollectingDestination {
        fn new() -> Self {
            Self {
                stored: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn stored_ids(&self) -> Vec<SegmentId> {
            self.stored
                .lock()
                .unwrap()
                .iter()
                .map(|(id, _)| *id)
                .collect()
        }
    }

    impl ArchivalDestination for CollectingDestination {
        fn store_segment(&self, segment_id: SegmentId, data: &[u8]) -> io::Result<()> {
            self.stored
                .lock()
                .unwrap()
                .push((segment_id, data.to_vec()));
            Ok(())
        }
    }

    fn create_segment_file(dir: &Path, id: u32, content: &[u8]) {
        let path = dir.join(format!("{:08}.{SEGMENT_FILE_EXTENSION}", id));
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn sidecar_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = ArchivalSidecar::new(dir.path().join("archival.state"));

        let state = sidecar.load().unwrap();
        assert!(state.last_archived_segment.is_none());

        let updated = ArchivalState {
            last_archived_segment: Some(SegmentId::new(42)),
        };
        sidecar.save(&updated).unwrap();

        let loaded = sidecar.load().unwrap();
        assert_eq!(loaded.last_archived_segment, Some(SegmentId::new(42)));
    }

    #[test]
    fn sidecar_missing_file_returns_empty() {
        let dir = tempfile::tempdir().unwrap();
        let sidecar = ArchivalSidecar::new(dir.path().join("nonexistent.state"));
        let state = sidecar.load().unwrap();
        assert!(state.last_archived_segment.is_none());
    }

    #[test]
    fn list_segment_files_sorts_ascending() {
        let dir = tempfile::tempdir().unwrap();
        create_segment_file(dir.path(), 5, b"e");
        create_segment_file(dir.path(), 1, b"a");
        create_segment_file(dir.path(), 3, b"c");
        std::fs::write(dir.path().join("notes.txt"), b"ignored").unwrap();

        let ids = list_segment_files(dir.path()).unwrap();
        assert_eq!(
            ids,
            vec![SegmentId::new(1), SegmentId::new(3), SegmentId::new(5)]
        );
    }

    #[test]
    fn list_segment_files_empty_dir() {
        let dir = tempfile::tempdir().unwrap();
        let ids = list_segment_files(dir.path()).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn list_segment_files_missing_dir() {
        let ids = list_segment_files(Path::new("/nonexistent/dir")).unwrap();
        assert!(ids.is_empty());
    }

    #[test]
    fn no_segments_no_archival() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();

        let dest = CollectingDestination::new();
        let dest_check = dest.clone();

        let archiver =
            ContinuousArchiver::new(seg_dir, dir.path().join("archival.state"), Box::new(dest));

        let result = archiver.run_pass().unwrap();
        assert_eq!(result.segments_archived, 0);
        assert_eq!(result.bytes_archived, 0);
        assert!(dest_check.stored_ids().is_empty());
    }

    #[test]
    fn single_active_segment_not_archived() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();
        create_segment_file(&seg_dir, 0, b"active segment data");

        let dest = CollectingDestination::new();
        let dest_check = dest.clone();

        let archiver =
            ContinuousArchiver::new(seg_dir, dir.path().join("archival.state"), Box::new(dest));

        let result = archiver.run_pass().unwrap();
        assert_eq!(result.segments_archived, 0);
        assert!(dest_check.stored_ids().is_empty());
    }

    #[test]
    fn archives_sealed_segments() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();
        create_segment_file(&seg_dir, 0, b"sealed-0");
        create_segment_file(&seg_dir, 1, b"sealed-1");
        create_segment_file(&seg_dir, 2, b"active");

        let dest = CollectingDestination::new();
        let dest_check = dest.clone();

        let archiver =
            ContinuousArchiver::new(seg_dir, dir.path().join("archival.state"), Box::new(dest));

        let result = archiver.run_pass().unwrap();
        assert_eq!(result.segments_archived, 2);
        assert_eq!(result.bytes_archived, 16);

        let stored = dest_check.stored_ids();
        assert_eq!(stored, vec![SegmentId::new(0), SegmentId::new(1)]);
    }

    #[test]
    fn incremental_archival_skips_already_archived() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();
        create_segment_file(&seg_dir, 0, b"sealed-0");
        create_segment_file(&seg_dir, 1, b"sealed-1");
        create_segment_file(&seg_dir, 2, b"sealed-2");
        create_segment_file(&seg_dir, 3, b"active");

        let sidecar_path = dir.path().join("archival.state");
        ArchivalSidecar::new(sidecar_path.clone())
            .save(&ArchivalState {
                last_archived_segment: Some(SegmentId::new(0)),
            })
            .unwrap();

        let dest = CollectingDestination::new();
        let dest_check = dest.clone();

        let archiver = ContinuousArchiver::new(seg_dir, sidecar_path.clone(), Box::new(dest));

        let result = archiver.run_pass().unwrap();
        assert_eq!(result.segments_archived, 2);

        let stored = dest_check.stored_ids();
        assert_eq!(stored, vec![SegmentId::new(1), SegmentId::new(2)]);

        let final_state = ArchivalSidecar::new(sidecar_path).load().unwrap();
        assert_eq!(final_state.last_archived_segment, Some(SegmentId::new(2)));
    }

    #[test]
    fn sidecar_updated_per_segment_for_crash_safety() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();
        create_segment_file(&seg_dir, 0, b"sealed-0");
        create_segment_file(&seg_dir, 1, b"sealed-1");
        create_segment_file(&seg_dir, 2, b"active");

        struct FailOnSecondDestination {
            call_count: Mutex<u32>,
        }
        impl ArchivalDestination for FailOnSecondDestination {
            fn store_segment(&self, _id: SegmentId, _data: &[u8]) -> io::Result<()> {
                let mut count = self.call_count.lock().unwrap();
                *count += 1;
                match *count {
                    1 => Ok(()),
                    _ => Err(io::Error::other("simulated failure")),
                }
            }
        }

        let sidecar_path = dir.path().join("archival.state");

        let archiver = ContinuousArchiver::new(
            seg_dir,
            sidecar_path.clone(),
            Box::new(FailOnSecondDestination {
                call_count: Mutex::new(0),
            }),
        );

        let err = archiver.run_pass().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);

        let state = ArchivalSidecar::new(sidecar_path).load().unwrap();
        assert_eq!(state.last_archived_segment, Some(SegmentId::new(0)));
    }

    #[test]
    fn idempotent_rerun_after_full_archival() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();
        create_segment_file(&seg_dir, 0, b"sealed-0");
        create_segment_file(&seg_dir, 1, b"sealed-1");
        create_segment_file(&seg_dir, 2, b"active");

        let sidecar_path = dir.path().join("archival.state");

        let dest1 = CollectingDestination::new();
        let dest1_check = dest1.clone();
        let archiver1 =
            ContinuousArchiver::new(seg_dir.clone(), sidecar_path.clone(), Box::new(dest1));
        archiver1.run_pass().unwrap();
        assert_eq!(dest1_check.stored_ids().len(), 2);

        let dest2 = CollectingDestination::new();
        let dest2_check = dest2.clone();
        let archiver2 = ContinuousArchiver::new(seg_dir, sidecar_path, Box::new(dest2));
        let result = archiver2.run_pass().unwrap();
        assert_eq!(result.segments_archived, 0);
        assert!(dest2_check.stored_ids().is_empty());
    }

    #[test]
    fn new_segments_after_initial_archival() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();
        create_segment_file(&seg_dir, 0, b"sealed-0");
        create_segment_file(&seg_dir, 1, b"active");

        let sidecar_path = dir.path().join("archival.state");

        let dest1 = CollectingDestination::new();
        let archiver1 =
            ContinuousArchiver::new(seg_dir.clone(), sidecar_path.clone(), Box::new(dest1));
        let r1 = archiver1.run_pass().unwrap();
        assert_eq!(r1.segments_archived, 1);

        create_segment_file(&seg_dir, 2, b"new-active");

        let dest2 = CollectingDestination::new();
        let dest2_check = dest2.clone();
        let archiver2 = ContinuousArchiver::new(seg_dir, sidecar_path, Box::new(dest2));
        let r2 = archiver2.run_pass().unwrap();
        assert_eq!(r2.segments_archived, 1);
        assert_eq!(dest2_check.stored_ids(), vec![SegmentId::new(1)]);
    }

    #[test]
    fn local_destination_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        let dest_dir = dir.path().join("archive");

        let dest = LocalArchivalDestination::new(dest_dir.clone()).unwrap();

        let payload = b"segment data here";
        dest.store_segment(SegmentId::new(5), payload).unwrap();

        let written =
            std::fs::read(dest_dir.join(format!("00000005.{SEGMENT_FILE_EXTENSION}"))).unwrap();
        assert_eq!(written, payload);
    }

    #[test]
    fn local_destination_atomic_overwrite() {
        let dir = tempfile::tempdir().unwrap();
        let dest_dir = dir.path().join("archive");

        let dest = LocalArchivalDestination::new(dest_dir.clone()).unwrap();

        dest.store_segment(SegmentId::new(1), b"first").unwrap();
        dest.store_segment(SegmentId::new(1), b"second").unwrap();

        let written =
            std::fs::read(dest_dir.join(format!("00000001.{SEGMENT_FILE_EXTENSION}"))).unwrap();
        assert_eq!(written, b"second");

        assert!(
            !dest_dir
                .join(format!("00000001.{SEGMENT_FILE_EXTENSION}.tmp"))
                .exists()
        );
    }

    #[test]
    fn archived_data_matches_source() {
        let dir = tempfile::tempdir().unwrap();
        let seg_dir = dir.path().join("segments");
        std::fs::create_dir_all(&seg_dir).unwrap();

        let content_0 = b"sealed segment zero content with some bulk data";
        let content_1 = b"sealed segment one with different content";
        create_segment_file(&seg_dir, 0, content_0);
        create_segment_file(&seg_dir, 1, content_1);
        create_segment_file(&seg_dir, 2, b"active");

        let dest = CollectingDestination::new();
        let dest_check = dest.clone();

        let archiver =
            ContinuousArchiver::new(seg_dir, dir.path().join("archival.state"), Box::new(dest));
        archiver.run_pass().unwrap();

        let stored = dest_check.stored.lock().unwrap();
        assert_eq!(stored[0].1, content_0);
        assert_eq!(stored[1].1, content_1);
    }
}
