use std::path::PathBuf;
use std::sync::Arc;

use tranquil_store::SimulatedIO;
use tranquil_store::StorageIO;
use tranquil_store::eventlog::{SegmentId, SegmentManager};

#[test]
fn concurrent_reader_survives_evict_on_segment_delete() {
    let sim: Arc<SimulatedIO> = Arc::new(SimulatedIO::pristine(0x1eed7a11));
    let segments_dir = PathBuf::from("/segments");

    let manager = Arc::new(
        SegmentManager::new(Arc::clone(&sim), segments_dir.clone(), 1 << 20).unwrap(),
    );

    let seg_id = SegmentId::new(1);

    let write_handle = manager.open_for_append(seg_id).unwrap();
    sim.write_at(write_handle.fd(), 0, b"arbitrary seed bytes for the segment")
        .unwrap();
    sim.sync(write_handle.fd()).unwrap();
    sim.sync_dir(&segments_dir).unwrap();
    drop(write_handle);

    let ready_to_evict = Arc::new(std::sync::Barrier::new(2));
    let evict_done = Arc::new(std::sync::Barrier::new(2));

    let reader_manager = Arc::clone(&manager);
    let reader_io = Arc::clone(&sim);
    let reader_ready = Arc::clone(&ready_to_evict);
    let reader_done = Arc::clone(&evict_done);

    let reader = std::thread::spawn(move || {
        let read_handle = reader_manager.open_for_read(seg_id).unwrap();
        reader_ready.wait();
        reader_done.wait();
        reader_io.file_size(read_handle.fd())
    });

    ready_to_evict.wait();
    manager.delete_segment(seg_id).unwrap();
    evict_done.wait();

    let read_result = reader.join().unwrap();
    assert!(
        read_result.is_ok(),
        "read against a FileId obtained before delete_segment must still succeed; \
         SegmentManager's delete_segment / rollback_rotation close the fd while a reader holds it. \
         error: {:?}",
        read_result.err()
    );
}
