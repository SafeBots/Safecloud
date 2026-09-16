Vendored from https://github.com/ffmpegwasm/ffmpeg.wasm

`ffmpeg.js`, `814.ffmpeg.js` — @ffmpeg/ffmpeg, MIT License:

Copyright (c) ffmpeg.wasm contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

---

`core/ffmpeg-core.js`, `core/ffmpeg-core.wasm` — @ffmpeg/core, a WebAssembly
build of FFmpeg itself, GPL-2.0-or-later License (this build was configured
with `--enable-gpl`, which pulls in GPL-only components such as libx264, so
the resulting binary as a whole is GPL rather than FFmpeg's default LGPL).
See https://www.ffmpeg.org/legal.html and
https://github.com/ffmpegwasm/ffmpeg.wasm-core for the full FFmpeg build
configuration and license text.
