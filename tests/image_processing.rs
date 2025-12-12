use bspds::image::{ImageProcessor, ImageError, OutputFormat, THUMB_SIZE_FEED, THUMB_SIZE_FULL, DEFAULT_MAX_FILE_SIZE};
use image::{DynamicImage, ImageFormat};
use std::io::Cursor;

fn create_test_png(width: u32, height: u32) -> Vec<u8> {
    let img = DynamicImage::new_rgb8(width, height);
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png).unwrap();
    buf
}

fn create_test_jpeg(width: u32, height: u32) -> Vec<u8> {
    let img = DynamicImage::new_rgb8(width, height);
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg).unwrap();
    buf
}

fn create_test_gif(width: u32, height: u32) -> Vec<u8> {
    let img = DynamicImage::new_rgb8(width, height);
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Gif).unwrap();
    buf
}

fn create_test_webp(width: u32, height: u32) -> Vec<u8> {
    let img = DynamicImage::new_rgb8(width, height);
    let mut buf = Vec::new();
    img.write_to(&mut Cursor::new(&mut buf), ImageFormat::WebP).unwrap();
    buf
}

#[test]
fn test_process_png() {
    let processor = ImageProcessor::new();
    let data = create_test_png(500, 500);
    let result = processor.process(&data, "image/png").unwrap();
    assert_eq!(result.original.width, 500);
    assert_eq!(result.original.height, 500);
}

#[test]
fn test_process_jpeg() {
    let processor = ImageProcessor::new();
    let data = create_test_jpeg(400, 300);
    let result = processor.process(&data, "image/jpeg").unwrap();
    assert_eq!(result.original.width, 400);
    assert_eq!(result.original.height, 300);
}

#[test]
fn test_process_gif() {
    let processor = ImageProcessor::new();
    let data = create_test_gif(200, 200);
    let result = processor.process(&data, "image/gif").unwrap();
    assert_eq!(result.original.width, 200);
    assert_eq!(result.original.height, 200);
}

#[test]
fn test_process_webp() {
    let processor = ImageProcessor::new();
    let data = create_test_webp(300, 200);
    let result = processor.process(&data, "image/webp").unwrap();
    assert_eq!(result.original.width, 300);
    assert_eq!(result.original.height, 200);
}

#[test]
fn test_thumbnail_feed_size() {
    let processor = ImageProcessor::new();
    let data = create_test_png(800, 600);
    let result = processor.process(&data, "image/png").unwrap();

    let thumb = result.thumbnail_feed.expect("Should generate feed thumbnail for large image");
    assert!(thumb.width <= THUMB_SIZE_FEED);
    assert!(thumb.height <= THUMB_SIZE_FEED);
}

#[test]
fn test_thumbnail_full_size() {
    let processor = ImageProcessor::new();
    let data = create_test_png(2000, 1500);
    let result = processor.process(&data, "image/png").unwrap();

    let thumb = result.thumbnail_full.expect("Should generate full thumbnail for large image");
    assert!(thumb.width <= THUMB_SIZE_FULL);
    assert!(thumb.height <= THUMB_SIZE_FULL);
}

#[test]
fn test_no_thumbnail_small_image() {
    let processor = ImageProcessor::new();
    let data = create_test_png(100, 100);
    let result = processor.process(&data, "image/png").unwrap();

    assert!(result.thumbnail_feed.is_none(), "Small image should not get feed thumbnail");
    assert!(result.thumbnail_full.is_none(), "Small image should not get full thumbnail");
}

#[test]
fn test_webp_conversion() {
    let processor = ImageProcessor::new().with_output_format(OutputFormat::WebP);
    let data = create_test_png(300, 300);
    let result = processor.process(&data, "image/png").unwrap();

    assert_eq!(result.original.mime_type, "image/webp");
}

#[test]
fn test_jpeg_output_format() {
    let processor = ImageProcessor::new().with_output_format(OutputFormat::Jpeg);
    let data = create_test_png(300, 300);
    let result = processor.process(&data, "image/png").unwrap();

    assert_eq!(result.original.mime_type, "image/jpeg");
}

#[test]
fn test_png_output_format() {
    let processor = ImageProcessor::new().with_output_format(OutputFormat::Png);
    let data = create_test_jpeg(300, 300);
    let result = processor.process(&data, "image/jpeg").unwrap();

    assert_eq!(result.original.mime_type, "image/png");
}

#[test]
fn test_max_dimension_enforced() {
    let processor = ImageProcessor::new().with_max_dimension(1000);
    let data = create_test_png(2000, 2000);
    let result = processor.process(&data, "image/png");

    assert!(matches!(result, Err(ImageError::TooLarge { .. })));
    if let Err(ImageError::TooLarge { width, height, max_dimension }) = result {
        assert_eq!(width, 2000);
        assert_eq!(height, 2000);
        assert_eq!(max_dimension, 1000);
    }
}

#[test]
fn test_file_size_limit() {
    let processor = ImageProcessor::new().with_max_file_size(100);
    let data = create_test_png(500, 500);
    let result = processor.process(&data, "image/png");

    assert!(matches!(result, Err(ImageError::FileTooLarge { .. })));
    if let Err(ImageError::FileTooLarge { size, max_size }) = result {
        assert!(size > 100);
        assert_eq!(max_size, 100);
    }
}

#[test]
fn test_default_max_file_size() {
    assert_eq!(DEFAULT_MAX_FILE_SIZE, 10 * 1024 * 1024);
}

#[test]
fn test_unsupported_format_rejected() {
    let processor = ImageProcessor::new();
    let data = b"this is not an image";
    let result = processor.process(data, "application/octet-stream");

    assert!(matches!(result, Err(ImageError::UnsupportedFormat(_))));
}

#[test]
fn test_corrupted_image_handling() {
    let processor = ImageProcessor::new();
    let data = b"\x89PNG\r\n\x1a\ncorrupted data here";
    let result = processor.process(data, "image/png");

    assert!(matches!(result, Err(ImageError::DecodeError(_))));
}

#[test]
fn test_aspect_ratio_preserved_landscape() {
    let processor = ImageProcessor::new();
    let data = create_test_png(1600, 800);
    let result = processor.process(&data, "image/png").unwrap();

    let thumb = result.thumbnail_full.expect("Should have thumbnail");
    let original_ratio = 1600.0 / 800.0;
    let thumb_ratio = thumb.width as f64 / thumb.height as f64;
    assert!((original_ratio - thumb_ratio).abs() < 0.1, "Aspect ratio should be preserved");
}

#[test]
fn test_aspect_ratio_preserved_portrait() {
    let processor = ImageProcessor::new();
    let data = create_test_png(800, 1600);
    let result = processor.process(&data, "image/png").unwrap();

    let thumb = result.thumbnail_full.expect("Should have thumbnail");
    let original_ratio = 800.0 / 1600.0;
    let thumb_ratio = thumb.width as f64 / thumb.height as f64;
    assert!((original_ratio - thumb_ratio).abs() < 0.1, "Aspect ratio should be preserved");
}

#[test]
fn test_mime_type_detection_auto() {
    let processor = ImageProcessor::new();
    let data = create_test_png(100, 100);
    let result = processor.process(&data, "application/octet-stream");

    assert!(result.is_ok(), "Should detect PNG format from data");
}

#[test]
fn test_is_supported_mime_type() {
    assert!(ImageProcessor::is_supported_mime_type("image/jpeg"));
    assert!(ImageProcessor::is_supported_mime_type("image/jpg"));
    assert!(ImageProcessor::is_supported_mime_type("image/png"));
    assert!(ImageProcessor::is_supported_mime_type("image/gif"));
    assert!(ImageProcessor::is_supported_mime_type("image/webp"));
    assert!(ImageProcessor::is_supported_mime_type("IMAGE/PNG"));
    assert!(ImageProcessor::is_supported_mime_type("Image/Jpeg"));

    assert!(!ImageProcessor::is_supported_mime_type("image/bmp"));
    assert!(!ImageProcessor::is_supported_mime_type("image/tiff"));
    assert!(!ImageProcessor::is_supported_mime_type("text/plain"));
    assert!(!ImageProcessor::is_supported_mime_type("application/json"));
}

#[test]
fn test_strip_exif() {
    let data = create_test_jpeg(100, 100);
    let result = ImageProcessor::strip_exif(&data);
    assert!(result.is_ok());
    let stripped = result.unwrap();
    assert!(!stripped.is_empty());
}

#[test]
fn test_with_thumbnails_disabled() {
    let processor = ImageProcessor::new().with_thumbnails(false);
    let data = create_test_png(2000, 2000);
    let result = processor.process(&data, "image/png").unwrap();

    assert!(result.thumbnail_feed.is_none(), "Thumbnails should be disabled");
    assert!(result.thumbnail_full.is_none(), "Thumbnails should be disabled");
}

#[test]
fn test_builder_chaining() {
    let processor = ImageProcessor::new()
        .with_max_dimension(2048)
        .with_max_file_size(5 * 1024 * 1024)
        .with_output_format(OutputFormat::Jpeg)
        .with_thumbnails(true);

    let data = create_test_png(500, 500);
    let result = processor.process(&data, "image/png").unwrap();
    assert_eq!(result.original.mime_type, "image/jpeg");
}

#[test]
fn test_processed_image_fields() {
    let processor = ImageProcessor::new();
    let data = create_test_png(500, 500);
    let result = processor.process(&data, "image/png").unwrap();

    assert!(!result.original.data.is_empty());
    assert!(!result.original.mime_type.is_empty());
    assert!(result.original.width > 0);
    assert!(result.original.height > 0);
}

#[test]
fn test_only_feed_thumbnail_for_medium_images() {
    let processor = ImageProcessor::new();
    let data = create_test_png(500, 500);
    let result = processor.process(&data, "image/png").unwrap();

    assert!(result.thumbnail_feed.is_some(), "Should have feed thumbnail");
    assert!(result.thumbnail_full.is_none(), "Should NOT have full thumbnail for 500px image");
}

#[test]
fn test_both_thumbnails_for_large_images() {
    let processor = ImageProcessor::new();
    let data = create_test_png(2000, 2000);
    let result = processor.process(&data, "image/png").unwrap();

    assert!(result.thumbnail_feed.is_some(), "Should have feed thumbnail");
    assert!(result.thumbnail_full.is_some(), "Should have full thumbnail for 2000px image");
}

#[test]
fn test_exact_threshold_boundary_feed() {
    let processor = ImageProcessor::new();

    let at_threshold = create_test_png(THUMB_SIZE_FEED, THUMB_SIZE_FEED);
    let result = processor.process(&at_threshold, "image/png").unwrap();
    assert!(result.thumbnail_feed.is_none(), "Exact threshold should not generate thumbnail");

    let above_threshold = create_test_png(THUMB_SIZE_FEED + 1, THUMB_SIZE_FEED + 1);
    let result = processor.process(&above_threshold, "image/png").unwrap();
    assert!(result.thumbnail_feed.is_some(), "Above threshold should generate thumbnail");
}

#[test]
fn test_exact_threshold_boundary_full() {
    let processor = ImageProcessor::new();

    let at_threshold = create_test_png(THUMB_SIZE_FULL, THUMB_SIZE_FULL);
    let result = processor.process(&at_threshold, "image/png").unwrap();
    assert!(result.thumbnail_full.is_none(), "Exact threshold should not generate thumbnail");

    let above_threshold = create_test_png(THUMB_SIZE_FULL + 1, THUMB_SIZE_FULL + 1);
    let result = processor.process(&above_threshold, "image/png").unwrap();
    assert!(result.thumbnail_full.is_some(), "Above threshold should generate thumbnail");
}
