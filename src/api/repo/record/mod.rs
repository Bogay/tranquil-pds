pub mod delete;
pub mod read;
pub mod write;

pub use delete::{DeleteRecordInput, delete_record};
pub use read::{GetRecordInput, ListRecordsInput, ListRecordsOutput, get_record, list_records};
pub use write::{
    CreateRecordInput, CreateRecordOutput, PutRecordInput, PutRecordOutput, create_record,
    put_record,
};
