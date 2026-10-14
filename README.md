# store-check

**Check an Android App Bundle (`.aab`) or APK for the Google Play 16 KB page-size requirement** —
without opening Android Studio.

Google Play now rejects apps targeting Android 15+ whose native libraries aren’t built with 16 KB
page alignment. `store-check` reads the native `.so` files straight out of your `.aab`/`.apk` and
tells you which ones (if any) will get your upload rejected.

- **Zero dependencies** (pure Node: a small ELF parser + ZIP reader)
- **Exits non-zero on failure** → drop it into CI
- Works on `.aab` and `.apk`

## Usage

```bash
npx @njweber/store-check ./app-release.aab
```

```
store-check — 16 KB page-size audit
artifact: ./app-release.aab

arm64-v8a
  ✓ libhermes.so  (p_align 0x4000)
  ✗ libfoo.so     NOT 16 KB aligned (p_align 0x1000)

FAIL — a 64-bit native lib is not 16 KB aligned. Google Play will reject this on Android 15+.
```

Exit codes: `0` aligned · `1` not aligned · `2` bad input.

## In CI

```yaml
- run: npx @njweber/store-check ./android/app/build/outputs/bundle/release/app-release.aab
```

## What it checks

For each `lib/<abi>/*.so` it parses the ELF program headers and reports the `p_align` of every
`PT_LOAD` segment. A lib is “16 KB aligned” when `p_align >= 0x4000` (16384). Only the 64-bit ABIs
(`arm64-v8a`, `x86_64`) gate the Play requirement; 32-bit ABIs are reported but don’t fail.

## If it fails

You can’t fix this by patching the ELF — the alignment has to come from the build. Upgrade your
toolchain: React Native `0.79+` / Expo SDK `53+` ship 16 KB-aligned prebuilts.

More notes: <https://booleanbuild.com/posts/16kb-page-size.html>

## GitHub Action

```yaml
- uses: nwebersoftware/store-check@main
  with:
    path: android/app/build/outputs/bundle/release/app-release.aab
```

Composite action — no npm install, no setup. Fails the job if a 64-bit lib isn't 16 KB aligned.

## License

MIT.
