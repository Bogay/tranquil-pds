use image::{DynamicImage, ImageFormat, ImageReader, imageops::FilterType};
use std::io::Cursor;

pub const THUMB_SIZE_FEED: u32 = 200;
pub const THUMB_SIZE_FULL: u32 = 1000;

#[derive(Debug, Clone)]
pub struct ProcessedImage {
    pub data: Vec<u8>,
    pub mime_type: String,
    pub width: u32,
    pub height: u32,
}

#[derive(Debug, Clone)]
pub struct ImageProcessingResult {
    pub original: ProcessedImage,
    pub thumbnail_feed: Option<ProcessedImage>,
    pub thumbnail_full: Option<ProcessedImage>,
}

#[derive(Debug, thiserror::Error)]
pub enum ImageError {
    #[error("Failed to decode image: {0}")]
    DecodeError(String),

    #[error("Failed to encode image: {0}")]
    EncodeError(String),

    #[error("Unsupported image format: {0}")]
    UnsupportedFormat(String),

    #[error("Image too large: {width}x{height} exceeds maximum {max_dimension}")]
    TooLarge {
        width: u32,
        height: u32,
        max_dimension: u32,
    },

    #[error("File too large: {size} bytes exceeds maximum {max_size} bytes")]
    FileTooLarge { size: usize, max_size: usize },
}

pub const DEFAULT_MAX_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB

pub struct ImageProcessor {
    max_dimension: u32,
    max_file_size: usize,
    output_format: OutputFormat,
    generate_thumbnails: bool,
}

#[derive(Debug, Clone, Copy)]
pub enum OutputFormat {
    WebP,
    Jpeg,
    Png,
    Original,
}

impl Default for ImageProcessor {
    fn default() -> Self {
        Self {
            max_dimension: 4096,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            output_format: OutputFormat::WebP,
            generate_thumbnails: true,
        }
    }
}

impl ImageProcessor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_dimension(mut self, max: u32) -> Self {
        self.max_dimension = max;
        self
    }

    pub fn with_max_file_size(mut self, max: usize) -> Self {
        self.max_file_size = max;
        self
    }

    pub fn with_output_format(mut self, format: OutputFormat) -> Self {
        self.output_format = format;
        self
    }

    pub fn with_thumbnails(mut self, generate: bool) -> Self {
        self.generate_thumbnails = generate;
        self
    }

    pub fn process(&self, data: &[u8], mime_type: &str) -> Result<ImageProcessingResult, ImageError> {
        if data.len() > self.max_file_size {
            return Err(ImageError::FileTooLarge {
                size: data.len(),
                max_size: self.max_file_size,
            });
        }

        let format = self.detect_format(mime_type, data)?;
        let img = self.decode_image(data, format)?;

        if img.width() > self.max_dimension || img.height() > self.max_dimension {
            return Err(ImageError::TooLarge {
                width: img.width(),
                height: img.height(),
                max_dimension: self.max_dimension,
            });
        }

        let original = self.encode_image(&img)?;

        let thumbnail_feed = if self.generate_thumbnails && (img.width() > THUMB_SIZE_FEED || img.height() > THUMB_SIZE_FEED) {
            Some(self.generate_thumbnail(&img, THUMB_SIZE_FEED)?)
        } else {
            None
        };

        let thumbnail_full = if self.generate_thumbnails && (img.width() > THUMB_SIZE_FULL || img.height() > THUMB_SIZE_FULL) {
            Some(self.generate_thumbnail(&img, THUMB_SIZE_FULL)?)
        } else {
            None
        };

        Ok(ImageProcessingResult {
            original,
            thumbnail_feed,
            thumbnail_full,
        })
    }

    fn detect_format(&self, mime_type: &str, data: &[u8]) -> Result<ImageFormat, ImageError> {
        match mime_type.to_lowercase().as_str() {
            "image/jpeg" | "image/jpg" => Ok(ImageFormat::Jpeg),
            "image/png" => Ok(ImageFormat::Png),
            "image/gif" => Ok(ImageFormat::Gif),
            "image/webp" => Ok(ImageFormat::WebP),
            _ => {
                if let Ok(format) = image::guess_format(data) {
                    Ok(format)
                } else {
                    Err(ImageError::UnsupportedFormat(mime_type.to_string()))
                }
            }
        }
    }

    fn decode_image(&self, data: &[u8], format: ImageFormat) -> Result<DynamicImage, ImageError> {
        let cursor = Cursor::new(data);
        let reader = ImageReader::with_format(cursor, format);
        reader
            .decode()
            .map_err(|e| ImageError::DecodeError(e.to_string()))
    }

    fn encode_image(&self, img: &DynamicImage) -> Result<ProcessedImage, ImageError> {
        let (data, mime_type) = match self.output_format {
            OutputFormat::WebP => {
                let mut buf = Vec::new();
                img.write_to(&mut Cursor::new(&mut buf), ImageFormat::WebP)
                    .map_err(|e| ImageError::EncodeError(e.to_string()))?;
                (buf, "image/webp".to_string())
            }
            OutputFormat::Jpeg => {
                let mut buf = Vec::new();
                img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Jpeg)
                    .map_err(|e| ImageError::EncodeError(e.to_string()))?;
                (buf, "image/jpeg".to_string())
            }
            OutputFormat::Png => {
                let mut buf = Vec::new();
                img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
                    .map_err(|e| ImageError::EncodeError(e.to_string()))?;
                (buf, "image/png".to_string())
            }
            OutputFormat::Original => {
                let mut buf = Vec::new();
                img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png)
                    .map_err(|e| ImageError::EncodeError(e.to_string()))?;
                (buf, "image/png".to_string())
            }
        };

        Ok(ProcessedImage {
            data,
            mime_type,
            width: img.width(),
            height: img.height(),
        })
    }

    fn generate_thumbnail(&self, img: &DynamicImage, max_size: u32) -> Result<ProcessedImage, ImageError> {
        let (orig_width, orig_height) = (img.width(), img.height());

        let (new_width, new_height) = if orig_width > orig_height {
            let ratio = max_size as f64 / orig_width as f64;
            (max_size, (orig_height as f64 * ratio) as u32)
        } else {
            let ratio = max_size as f64 / orig_height as f64;
            ((orig_width as f64 * ratio) as u32, max_size)
        };

        let thumb = img.resize(new_width, new_height, FilterType::Lanczos3);
        self.encode_image(&thumb)
    }

    pub fn is_supported_mime_type(mime_type: &str) -> bool {
        matches!(
            mime_type.to_lowercase().as_str(),
            "image/jpeg" | "image/jpg" | "image/png" | "image/gif" | "image/webp"
        )
    }

    pub fn strip_exif(data: &[u8]) -> Result<Vec<u8>, ImageError> {
        let format = image::guess_format(data)
            .map_err(|e| ImageError::DecodeError(e.to_string()))?;

        let cursor = Cursor::new(data);
        let img = ImageReader::with_format(cursor, format)
            .decode()
            .map_err(|e| ImageError::DecodeError(e.to_string()))?;

        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), format)
            .map_err(|e| ImageError::EncodeError(e.to_string()))?;

        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_image(width: u32, height: u32) -> Vec<u8> {
        let img = DynamicImage::new_rgb8(width, height);
        let mut buf = Vec::new();
        img.write_to(&mut Cursor::new(&mut buf), ImageFormat::Png).unwrap();
        buf
    }

    #[test]
    fn test_process_small_image() {
        let processor = ImageProcessor::new();
        let data = create_test_image(100, 100);

        let result = processor.process(&data, "image/png").unwrap();

        assert!(result.thumbnail_feed.is_none());
        assert!(result.thumbnail_full.is_none());
    }

    #[test]
    fn test_process_large_image_generates_thumbnails() {
        let processor = ImageProcessor::new();
        let data = create_test_image(2000, 1500);

        let result = processor.process(&data, "image/png").unwrap();

        assert!(result.thumbnail_feed.is_some());
        assert!(result.thumbnail_full.is_some());

        let feed_thumb = result.thumbnail_feed.unwrap();
        assert!(feed_thumb.width <= THUMB_SIZE_FEED);
        assert!(feed_thumb.height <= THUMB_SIZE_FEED);

        let full_thumb = result.thumbnail_full.unwrap();
        assert!(full_thumb.width <= THUMB_SIZE_FULL);
        assert!(full_thumb.height <= THUMB_SIZE_FULL);
    }

    #[test]
    fn test_webp_conversion() {
        let processor = ImageProcessor::new().with_output_format(OutputFormat::WebP);
        let data = create_test_image(500, 500);

        let result = processor.process(&data, "image/png").unwrap();
        assert_eq!(result.original.mime_type, "image/webp");
    }

    #[test]
    fn test_reject_too_large() {
        let processor = ImageProcessor::new().with_max_dimension(1000);
        let data = create_test_image(2000, 2000);

        let result = processor.process(&data, "image/png");
        assert!(matches!(result, Err(ImageError::TooLarge { .. })));
    }

    #[test]
    fn test_is_supported_mime_type() {
        assert!(ImageProcessor::is_supported_mime_type("image/jpeg"));
        assert!(ImageProcessor::is_supported_mime_type("image/png"));
        assert!(ImageProcessor::is_supported_mime_type("image/gif"));
        assert!(ImageProcessor::is_supported_mime_type("image/webp"));
        assert!(!ImageProcessor::is_supported_mime_type("image/bmp"));
        assert!(!ImageProcessor::is_supported_mime_type("text/plain"));
    }
}
