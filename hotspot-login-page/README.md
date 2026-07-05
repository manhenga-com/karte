# MikroTik Hotspot Login Page

This folder contains a standalone MikroTik Hotspot login page.

## Preview Locally

Serve this folder on a separate port:

```powershell
python -m http.server 8018 --directory hotspot-login-page
```

Open:

```text
http://127.0.0.1:8018/login.html
```

## Upload To MikroTik

1. Open WinBox.
2. Go to **Files**.
3. Open the router's `hotspot` folder.
4. Replace `login.html` with this `login.html`.
5. Keep a backup of the old MikroTik `login.html`.

The page uses these MikroTik variables and should remain named `login.html`:

- `$(link-login-only)`
- `$(link-orig)`
- `$(if error)`
- `$(error)`
- `$(ip)`
- `$(mac)`

The voucher code is submitted as both username and password.

