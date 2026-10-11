## Changes

### Version 0.25.0

Breaking changes:
- Added `BufRead` + `Seek` bound on many decoders.
- Use `ExtendedColorType` instead of `ColorType` when encoding.
- Removed `ImageOutputFormat`, `GenericImageView::bounds`, and several other
  deprecated items.
- Removed incremental decoding support and changed `ImageDecoder` so the trait
  is object safe.
- Pixel types are now `repr(transparent)` rather than `repr(C)`.
- Made color_quant dependency optional.
- Renamed some feature flags.

Structural changes:
- Increased MSRV to 1.67.1

Codec changes:
- Switched to image-webp for WebP encoding.
- Switched to zune-jpeg for JPEG decoding.
- Made the HDR decoder produce f32 images.

### Version 0.24.9

Structural changes:
