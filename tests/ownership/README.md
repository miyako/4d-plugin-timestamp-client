# Ownership regressions

These ASan/UBSan tests cover 4D native ownership in the plugin's commands and in `support/4DPlugin-JSON.cpp`. They build the real plugin sources, the SDK classes in the Xcode/vcxproj builds, the full and unchanged bundled `4DPluginAPI.c`, and the bundled static OpenSSL. A synthetic `Call4D` engine tracks every engine string, picture, handle and object.

No timestamp authority is contacted:
- The plugin only uses memory BIOs and synthetic inputs.
- `connect()` and `getaddrinfo()` abort the harness if they are reached.

```sh
# fixed tree: every test must pass
tests/ownership/run.sh . fixed

# immutable baseline: defect/hardening tests must fail, controls must pass
mkdir /tmp/base && git archive <base-sha> | tar -x -C /tmp/base
tests/ownership/run.sh /tmp/base baseline
```

This only covers macOS. The Windows build and the real 4D runtime are not exercised.
