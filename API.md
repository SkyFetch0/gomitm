# v0.1 frozen API

Do not change:

- `Decider` method set (`OnConnect`, `OnRequest`, `OnFlow`)
- `Action` (`Passthrough`, `Terminate`)
- `New`, `Engine.Handle`, `Engine.WithMaxBody`
- `LoadOrCreateCA`, `CertManager.CACertPEM`, `CertManager.ServerConfig`
- `IsTLS`, `PeekSNI`, `PeekHTTPHost`
- `Flow` existing fields; adding fields is OK
- `DefaultMaxBody`

gomitm must stay stdlib-only and must not import skydst.
