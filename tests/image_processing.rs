use bspds::image::{
    DEFAULT_MAX_FILE_SIZE, ImageError, ImageProcessor, OutputFormat, THUMB_SIZE_FEED,
    THUMB_SIZE_FULL,
};
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
fn test_format_support() {
    let processor = ImageProcessor::new();

    let png = create_test_png(500, 500);
    let result = processor.process(&png, "image/png").unwrap();
    assert_eq!(result.original.width, 500);
    assert_eq!(result.original.height, 500);

    let jpeg = create_test_jpeg(400, 300);
    let result = processor.process(&jpeg, "image/jpeg").unwrap();
    assert_eq!(result.original.width, 400);
    assert_eq!(result.original.height, 300);

    let gif = create_test_gif(200, 200);
    let result = processor.process(&gif, "image/gif").unwrap();
    assert_eq!(result.original.width, 200);

    let webp = create_test_webp(300, 200);
    let result = processor.process(&webp, "image/webp").unwrap();
    assert_eq!(result.original.width, 300);
}

#[test]
fn test_thumbnail_generation() {
    let processor = ImageProcessor::new();

    let small = create_test_png(100, 100);
    let result = processor.process(&small, "image/png").unwrap();
    assert!(result.thumbnail_feed.is_none(), "Small image should not get feed thumbnail");
    assert!(result.thumbnail_full.is_none(), "Small image should not get full thumbnail");

    let medium = create_test_png(500, 500);
    let result = processor.process(&medium, "image/png").unwrap();
    assert!(result.thumbnail_feed.is_some(), "Medium image should have feed thumbnail");
    assert!(result.thumbnail_full.is_none(), "Medium image should NOT have full thumbnail");

    let large = create_test_png(2000, 2000);
    let result = processor.process(&large, "image/png").unwrap();
    assert!(result.thumbnail_feed.is_some(), "Large image should have feed thumbnail");
    assert!(result.thumbnail_full.is_some(), "Large image should have full thumbnail");
    let thumb = result.thumbnail_feed.unwrap();
    assert!(thumb.width <= THUMB_SIZE_FEED && thumb.height <= THUMB_SIZE_FEED);
    let full = result.thumbnail_full.unwrap();
    assert!(full.width <= THUMB_SIZE_FULL && full.height <= THUMB_SIZE_FULL);

    let at_feed = create_test_png(THUMB_SIZE_FEED, THUMB_SIZE_FEED);
    let above_feed = create_test_png(THUMB_SIZE_FEED + 1, THUMB_SIZE_FEED + 1);
    assert!(processor.process(&at_feed, "image/png").unwrap().thumbnail_feed.is_none());
    assert!(processor.process(&above_feed, "image/png").unwrap().thumbnail_feed.is_some());

    let at_full = create_test_png(THUMB_SIZE_FULL, THUMB_SIZE_FULL);
    let above_full = create_test_png(THUMB_SIZE_FULL + 1, THUMB_SIZE_FULL + 1);
    assert!(processor.process(&at_full, "image/png").unwrap().thumbnail_full.is_none());
    assert!(processor.process(&above_full, "image/png").unwrap().thumbnail_full.is_some());

    let disabled = ImageProcessor::new().with_thumbnails(false);
    let result = disabled.process(&large, "image/png").unwrap();
    assert!(result.thumbnail_feed.is_none() && result.thumbnail_full.is_none());
}

#[test]
fn test_output_format_conversion() {
    let png = create_test_png(300, 300);
    let jpeg = create_test_jpeg(300, 300);

    let webp_proc = ImageProcessor::new().with_output_format(OutputFormat::WebP);
    assert_eq!(webp_proc.process(&png, "image/png").unwrap().original.mime_type, "image/webp");

    let jpeg_proc = ImageProcessor::new().with_output_format(OutputFormat::Jpeg);
    assert_eq!(jpeg_proc.process(&png, "image/png").unwrap().original.mime_type, "image/jpeg");

    let png_proc = ImageProcessor::new().with_output_format(OutputFormat::Png);
    assert_eq!(png_proc.process(&jpeg, "image/jpeg").unwrap().original.mime_type, "image/png");
}

#[test]
fn test_size_and_dimension_limits() {
    assert_eq!(DEFAULT_MAX_FILE_SIZE, 10 * 1024 * 1024);

    let max_dim = ImageProcessor::new().with_max_dimension(1000);
    let large = create_test_png(2000, 2000);
    let result = max_dim.process(&large, "image/png");
    assert!(matches!(result, Err(ImageError::TooLarge { width: 2000, height: 2000, max_dimension: 1000 })));

    let max_file = ImageProcessor::new().with_max_file_size(100);
    let data = create_test_png(500, 500);
    let result = max_file.process(&data, "image/png");
    assert!(matches!(result, Err(ImageError::FileTooLarge { max_size: 100, .. })));
}

#[test]
fn test_error_handling() {
    let processor = ImageProcessor::new();

    let result = processor.process(b"this is not an image", "application/octet-stream");
    assert!(matches!(result, Err(ImageError::UnsupportedFormat(_))));

    let result = processor.process(b"\x89PNG\r\n\x1a\ncorrupted data here", "image/png");
    assert!(matches!(result, Err(ImageError::DecodeError(_))));
}

#[test]
fn test_aspect_ratio_preservation() {
    let processor = ImageProcessor::new();

    let landscape = create_test_png(1600, 800);
    let result = processor.process(&landscape, "image/png").unwrap();
    let thumb = result.thumbnail_full.unwrap();
    let original_ratio = 1600.0 / 800.0;
    let thumb_ratio = thumb.width as f64 / thumb.height as f64;
    assert!((original_ratio - thumb_ratio).abs() < 0.1);

    let portrait = create_test_png(800, 1600);
    let result = processor.process(&portrait, "image/png").unwrap();
    let thumb = result.thumbnail_full.unwrap();
    let original_ratio = 800.0 / 1600.0;
    let thumb_ratio = thumb.width as f64 / thumb.height as f64;
    assert!((original_ratio - thumb_ratio).abs() < 0.1);
}

#[test]
fn test_utilities_and_builder() {
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

    let data = create_test_png(100, 100);
    let processor = ImageProcessor::new();
    let result = processor.process(&data, "application/octet-stream");
    assert!(result.is_ok(), "Should detect PNG format from data");

    let jpeg = create_test_jpeg(100, 100);
    let stripped = ImageProcessor::strip_exif(&jpeg).unwrap();
    assert!(!stripped.is_empty());

    let processor = ImageProcessor::new()
        .with_max_dimension(2048)
        .with_max_file_size(5 * 1024 * 1024)
        .with_output_format(OutputFormat::Jpeg)
        .with_thumbnails(true);
    let data = create_test_png(500, 500);
    let result = processor.process(&data, "image/png").unwrap();
    assert_eq!(result.original.mime_type, "image/jpeg");
    assert!(!result.original.data.is_empty());
    assert!(result.original.width > 0 && result.original.height > 0);
}
