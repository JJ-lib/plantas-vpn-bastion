# Synthetic site example

This example documents the boundary between a generated site overlay and external secrets. The addresses below use documentation ranges and must never be replaced with live customer data in a public pull request.

```text
operator -> bastion listener -> site HAProxy -> VPN namespace -> 192.0.2.20:80
```

The real provider profile, PSK, certificate, and password belong in the protected deployment system. Use `templates/` when creating a reviewed site overlay outside this repository.
